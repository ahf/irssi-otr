/*
 * Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) 2008 - Uli Meis <a.sporto+bee@gmail.com>
 *               2012 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#define _GNU_SOURCE
#include <glib.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <signal.h>
#include <unistd.h>

#include "key.h"

/*
 * Status of key generation.
 */
enum key_gen_status {
	KEY_GEN_IDLE		= 0,
	KEY_GEN_RUNNING		= 1,
	KEY_GEN_FINISHED	= 2,
	KEY_GEN_ERROR		= 3,
};

/*
 * Data of the state of key generation.
 */
struct key_gen_data {
	struct otr_user_state *ustate;
	char *account_name;
	char *key_file_path;
	enum key_gen_status status;
	gcry_error_t gcry_error;
	void *newkey;
};

/*
 * Event from the key generation process.
 */
struct key_gen_event {
	enum key_gen_status status;
	gcry_error_t error;
};

/*
 * Key generation process.
 */
struct key_gen_worker {
	int tag;
	GIOChannel *pipes[2];
};

/*
 * Key generation data for the thread in charge of creating the key.
 */
static struct key_gen_data key_gen_state = {
	.status = KEY_GEN_IDLE,
	.gcry_error = GPG_ERR_NO_ERROR,
};

/*
 * Build file path concatenate to the irssi config dir.
 */
static char *file_path_build(const char *path)
{
	int ret;
	char *filename;

	if (path == NULL) {
		path = "";
	}

	/* Either NULL or the filename is returned here which is valid. */
	ret = asprintf(&filename, "%s%s", get_irssi_dir(), path);
	if (ret < 0) {
		filename = NULL;
	}

	return filename;
}

/*
 * Blocking write on a GIOChannel.
 * FIXME: Should be refactored in Irssi.
 */
static int g_io_channel_write_block(GIOChannel *channel, void *data, int len)
{
	gsize ret;
	int sent;
	GIOStatus status;

	sent = 0;

	do {
		status = g_io_channel_write_chars(channel, (char *) data + sent, len - sent, &ret, NULL);
		sent += ret;
	} while (sent < len && status != G_IO_STATUS_ERROR);

	return sent < len ? -1 : 0;
}

/*
 * Blocking read on a GIOChannel.
 * FIXME: Should be refactored in Irssi.
 */
static int g_io_channel_read_block(GIOChannel *channel, void *data, int len)
{
	time_t maxwait;
	gsize ret;
	int received;
	GIOStatus status;

	maxwait = time(NULL) + 2;
	received = 0;

	do {
		status = g_io_channel_read_chars(channel, (char *) data + received, len - received, &ret, NULL);
		received += ret;
	} while (received < len && time(NULL) < maxwait && status != G_IO_STATUS_ERROR && status != G_IO_STATUS_EOF);

	return received < len ? -1 : 0;
}

/*
 * Emit a key generation status event.
 */
static void emit_event(GIOChannel *pipe, enum key_gen_status status, gcry_error_t error)
{
	struct key_gen_event event;

	g_assert(pipe != NULL);

	event.status = status;
	event.error = error;

	g_io_channel_write_block(pipe, &event, sizeof(event));
}

/*
 * Reset key generation state and status is IDLE.
 */
static void reset_key_gen_state(void)
{
	/* Safety. */
	if (key_gen_state.key_file_path != NULL) {
		free(key_gen_state.key_file_path);
	}

	/* Pointer dup when key_gen_run is called. */
	if (key_gen_state.account_name != NULL) {
		free(key_gen_state.account_name);
	}

	/* Nullify everything. */
	memset(&key_gen_state, 0, sizeof(key_gen_state));
	key_gen_state.status = KEY_GEN_IDLE;
	key_gen_state.gcry_error = GPG_ERR_NO_ERROR;
}

/*
 * Read status event from key generation worker.
 */
static void read_key_gen_status(struct key_gen_worker *worker, GIOChannel *pipe)
{
	struct key_gen_event event;

	g_assert(worker != NULL);

	fcntl(g_io_channel_unix_get_fd(pipe), F_SETFL, O_NONBLOCK);

	if (g_io_channel_read_block(pipe, &event, sizeof(event)) == -1) {
		g_warning("Error: %s", g_strerror(errno));
		return;
	}

	key_gen_state.status = event.status;
	key_gen_state.gcry_error = event.error;

	g_warning("Status: %d", event.status);

	if (event.status == KEY_GEN_FINISHED || event.status == KEY_GEN_ERROR) {
		/* Worker is done. */
		g_source_remove(worker->tag);

		g_io_channel_shutdown(worker->pipes[0], TRUE, NULL);
		g_io_channel_unref(worker->pipes[0]);

		g_io_channel_shutdown(worker->pipes[1], TRUE, NULL);
		g_io_channel_unref(worker->pipes[1]);

		g_free(worker);

		key_gen_check();
	}
}

/*
 * Generate OTR key. This function is executed as a child process.
 *
 * NOTE: NO irssi interaction should be done here like emitting signals or else
 * it causes a segfaults of libperl.
 */
static void generate_key(GIOChannel *pipe)
{
	pid_t pid;

	pid = fork();

	if (pid > 0) {
		/* parent process */
		pidwait_add(pid);
		return;
	}

	if (pid != 0) {
		/* error */
		g_warning("generate_key(): fork() failed");
	}

	/* child process */
	gcry_error_t err;

	g_assert(key_gen_state.newkey != NULL);

	key_gen_state.status = KEY_GEN_RUNNING;
	emit_event(pipe, KEY_GEN_RUNNING, GPG_ERR_NO_ERROR);

	err = otrl_privkey_generate_calculate(key_gen_state.newkey);

	if (err != GPG_ERR_NO_ERROR) {
		emit_event(pipe, KEY_GEN_ERROR, err);
		_exit(99);
		return;
	}

	emit_event(pipe, KEY_GEN_FINISHED, GPG_ERR_NO_ERROR);

	_exit(99);
}

/*
 * Check key generation state and print message to user according to state.
 */
void key_gen_check(void)
{
	gcry_error_t err;

	g_warning("Key: %p", key_gen_state.newkey);
	g_warning("Path: %s", key_gen_state.key_file_path);
	g_warning("OTR state: %p", key_gen_state.ustate);

	if (key_gen_state.ustate != NULL) {
		g_warning("OTR state->otr_state: %p", key_gen_state.ustate->otr_state);
	}

	switch (key_gen_state.status) {
	case KEY_GEN_FINISHED:
		err = otrl_privkey_generate_finish(key_gen_state.ustate->otr_state, key_gen_state.newkey, key_gen_state.key_file_path);
		if (err != GPG_ERR_NO_ERROR) {
			IRSSI_MSG("Key generation finish state failed. Err: %s",
					gcry_strerror(err));
		} else {
			IRSSI_MSG("Key generation for %9%s%n completed",
					key_gen_state.account_name);
		}
		reset_key_gen_state();
		break;
	case KEY_GEN_ERROR:
		IRSSI_MSG("Key generation for %9%s%n failed. Err: %s (%d)",
				key_gen_state.account_name,
				gcry_strerror(key_gen_state.gcry_error),
				key_gen_state.gcry_error);
		reset_key_gen_state();
		break;
	case KEY_GEN_RUNNING:
	case KEY_GEN_IDLE:
		/* Do nothing */
		break;
	};
}

/*
 * Run key generation in a seperate process (takes ages). The other process
 * will rewrite the key file, we shouldn't change anything till it's done and
 * we've reloaded the keys.
 */
void key_gen_run(struct otr_user_state *ustate, const char *account_name)
{
	gcry_error_t err;
	struct key_gen_worker *worker;
	int fd[2];

	g_assert(ustate != NULL);
	g_assert(account_name != NULL);

	if (key_gen_state.status != KEY_GEN_IDLE) {
		IRSSI_INFO(NULL, NULL, "Key generation for %s is still in progress. ",
				"Please wait until completion before creating a new key.",
				key_gen_state.account_name);
		return;
	}

	/* Make sure the pointer does not go away during the proess. */
	key_gen_state.account_name = strdup(account_name);
	key_gen_state.ustate = ustate;

	/* Creating key file path. */
	key_gen_state.key_file_path = file_path_build(OTR_KEYFILE);
	if (key_gen_state.key_file_path == NULL) {
		IRSSI_INFO(NULL, NULL, "Key generation failed. ENOMEM");
		reset_key_gen_state();
		return;
	}

	IRSSI_MSG("Key generation started for %9%s%n", key_gen_state.account_name);

	err = otrl_privkey_generate_start(ustate->otr_state, account_name,
			OTR_PROTOCOL_ID, &key_gen_state.newkey);
	if (err != GPG_ERR_NO_ERROR || key_gen_state.newkey == NULL) {
		IRSSI_MSG("Key generation start failed. Err: %s", gcry_strerror(err));
		reset_key_gen_state();
		return;
	}

	if (pipe(fd) != 0) {
		IRSSI_INFO(NULL, NULL, "Key generation failed. Error: pipe()");
		reset_key_gen_state();
		return;
	}

	worker = g_new0(struct key_gen_worker, 1);

	if (worker == NULL) {
		IRSSI_INFO(NULL, NULL, "Key generation failed. Error: ENOMEM");
		reset_key_gen_state();
		return;
	}

	worker->pipes[0] = g_io_channel_new(fd[0]);
	worker->pipes[1] = g_io_channel_new(fd[1]);

	generate_key(worker->pipes[1]);

	worker->tag = g_input_add(worker->pipes[0], G_INPUT_READ, (GInputFunction)read_key_gen_status, worker);
}

/*
 * Write fingerprints to file.
 */
void key_write_fingerprints(struct otr_user_state *ustate)
{
	gcry_error_t err;
	char *filename;

	g_assert(ustate != NULL);

	filename = file_path_build(OTR_FINGERPRINTS_FILE);
	if (filename == NULL) {
		return;
	}

	err = otrl_privkey_write_fingerprints(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_DEBUG("Fingerprints saved to %9%s%9", filename);
	} else {
		IRSSI_DEBUG("Error writing fingerprints: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}

	free(filename);
}

/*
 * Write instance tags to file.
 */
void key_write_instags(struct otr_user_state *ustate)
{
	gcry_error_t err;
	char *filename;

	g_assert(ustate != NULL);

	filename = file_path_build(OTR_INSTAG_FILE);
	if (filename == NULL) {
		return;
	}

	err = otrl_instag_write(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_DEBUG("Instance tags saved in %9%s%9", filename);
	} else {
		IRSSI_DEBUG("Error saving instance tags: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}

	free(filename);
}

/*
 * Load private keys.
 */
void key_load(struct otr_user_state *ustate)
{
	int ret;
	gcry_error_t err;
	char *filename;

	g_assert(ustate != NULL);

	filename = file_path_build(OTR_KEYFILE);
	if (filename == NULL) {
		return;
	}

	ret = access(filename, F_OK);
	if (ret < 0) {
		IRSSI_DEBUG("No private keys found in %9%s%9", filename);
		free(filename);
		return;
	}

	err = otrl_privkey_read(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_DEBUG("Private keys loaded from %9%s%9", filename);
	} else {
		IRSSI_DEBUG("Error loading private keys: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}
}

/*
 * Load fingerprints.
 */
void key_load_fingerprints(struct otr_user_state *ustate)
{
	int ret;
	gcry_error_t err;
	char *filename;

	g_assert(ustate != NULL);

	filename = file_path_build(OTR_FINGERPRINTS_FILE);
	if (filename == NULL) {
		return;
	}

	ret = access(filename, F_OK);
	if (ret < 0) {
		IRSSI_DEBUG("No fingerprints found in %9%s%9", filename);
		free(filename);
		return;
	}

	err = otrl_privkey_read_fingerprints(ustate->otr_state, filename, NULL,
			NULL);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_DEBUG("Fingerprints loaded from %9%s%9", filename);
	} else {
		IRSSI_DEBUG("Error loading fingerprints: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}
}
