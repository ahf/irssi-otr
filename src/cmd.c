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
#include <stdio.h>

#include "cmd.h"
#include "key.h"

/*
 * /otr debug
 */
static void _cmd_debug(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	debug = !debug;
	if (debug) {
		IRSSI_INFO(NULL, NULL, "Debug on");
	} else {
		IRSSI_INFO(NULL, NULL, "Debug off");
	}
}

/*
 * /otr version 
 */
static void _cmd_version(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	IRSSI_INFO(NULL, NULL, "OTR module version: " VERSION);
}

/*
 * /otr help 
 */
static void _cmd_help(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	int ret;
	char *cmd_line;

	ret = asprintf(&cmd_line, "%sHELP otr", settings_get_str("cmdchars"));
	if (ret < 0) {
		return;
	}

	/* Call /help otr instread of duplicating the text output. */
	signal_emit("send command", 3, cmd_line, server, NULL);

	free(cmd_line);
}

/*
 * /otr finish 
 */
static void _cmd_finish(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	if (server == NULL || target == NULL) {
		IRSSI_NOTICE(server, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		return;
	}

	otr_finish(server, target);
}

/*
 * /otr trust [FP]
 */
static void _cmd_trust(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	int argc;
	char **argv;
	char str_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN], *fp = NULL;

	utils_explode_args(data, &argv, &argc);

	if (argc == 5) {
		utils_hash_parts_to_readable_hash((const char **) argv, str_fp);
		fp = str_fp;
	} else if (server == NULL || argc != 0) {
		/* If no IRSSI or some arguments (not 5), bad command. */
		IRSSI_NOTICE(server, target, "Usage %9/otr trust [FP]%9 "
				"where FP is the five part of the fingerprint listed by "
				"%9/otr contexts%9 or do the command inside an OTR session "
				"private message window.");
		utils_free_args(&argv, argc);
		return;
	}

	otr_trust(server, target, fp, ustate);

	utils_free_args(&argv, argc);
	return;
}

/*
 * /otr authabort
 */
static void _cmd_authabort(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	if (server == NULL || target == NULL) {
		IRSSI_NOTICE(server, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		return;
	}

	otr_auth_abort(server, target);
}

/*
 * /otr genkey mynick@irc.server.net
 */
static void _cmd_genkey(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	int argc;
	char **argv;

	utils_explode_args(data, &argv, &argc);

	if (argc) {
		if (strchr(argv[0], '@')) {
			key_gen_run(ustate, argv[0]);
		} else {
			IRSSI_INFO(NULL, NULL, "I need an account name. "
					"Try something like /otr genkey mynick@irc.server.net");
		}
	} else {
		IRSSI_INFO(NULL, NULL, "I need an account name. "
				"Try something like /otr genkey mynick@irc.server.net");
	}

	utils_free_args(&argv, argc);
}

/*
 * Authentication with a question.
 *
 * /otr authq [QUESTION] SECRET
 */
static void _cmd_authq(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	int ret;
	char *question = NULL, *secret = NULL;

	if (server == NULL || target == NULL) {
		IRSSI_NOTICE(server, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		return;
	}

	/*
	 * Returns a negative value if the command arguments are not formatted
	 * correctly or missing. Note, an empty question or secret is valid.
	 */
	ret = utils_io_extract_smp(data, &question, &secret);
	if (ret < 0) {
		IRSSI_NOTICE(server, target, "Usage: %9/otr authq [QUESTION] "
				"SECRET%9");
		return;
	}

	otr_auth(server, target, question, secret);

	free(question);
	free(secret);
}

/*
 * /otr auth SECRET
 */
static void _cmd_auth(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	int ret;
	char *secret = NULL;

	if (server == NULL || target == NULL) {
		IRSSI_NOTICE(server, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		return;
	}

	ret = utils_auth_extract_secret(data, &secret);
	if (ret < 0) {
		IRSSI_NOTICE(server, target, "Huh... I need a secret here James.");
		return;
	}

	otr_auth(server, target, NULL, secret);
	free(secret);
}

/*
 * /otr contexts
 */
static void _cmd_contexts(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	otr_contexts(ustate);
}

/*
 * /otr init
 */
static void _cmd_init(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	ConnContext *ctx;

	/* No server object, just ignore the request */
	if (server == NULL || target == NULL) {
		IRSSI_NOTICE(server, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		return;
	}

	ctx = otr_find_context(server, target, 0);
	if (ctx && ctx->msgstate == OTRL_MSGSTATE_ENCRYPTED) {
		IRSSI_NOTICE(server, target, "Already secure!");
		return;
	}

	IRSSI_NOTICE(server, target, "Initiating OTR session...");

	/*
	 * Irssi does not handle well the HTML tag in the default OTR query message
	 * so just send the OTR tag instead. Contact me for a better fix! :)
	 */
	irssi_send_message(server, target, "?OTRv23?");
}

/*
 * /otr forget [FP]
 */
static void _cmd_forget(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	int argc;
	char **argv;
	char str_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN], *fp = NULL;

	utils_explode_args(data, &argv, &argc);

	if (argc == 5) {
		utils_hash_parts_to_readable_hash((const char **) argv, str_fp);
		fp = str_fp;
	} else if (server == NULL || argc != 0) {
		/* If no IRSSI or some arguments (not 5), bad command. */
		IRSSI_NOTICE(server, target, "Usage %9/otr forget [FP]%9 "
				"where FP is the five part of the fingerprint listed by "
				"%9/otr contexts%9 or do the command inside an OTR session "
				"private message window");
		utils_free_args(&argv, argc);
		return;
	}

	/* Trigger the forget action. */
	otr_forget(server, target, fp, ustate);

	utils_free_args(&argv, argc);
}

/*
 * /otr distrust [FP]
 */
static void _cmd_distrust(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	int argc;
	char **argv;
	char str_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN], *fp = NULL;

	utils_explode_args(data, &argv, &argc);

	if (argc == 5) {
		utils_hash_parts_to_readable_hash((const char **) argv, str_fp);
		fp = str_fp;
	} else if (server == NULL || argc != 0) {
		/* If no IRSSI or some arguments (not 5), bad command. */
		IRSSI_NOTICE(server, target, "Usage %9/otr distrust [FP]%9 "
				"where FP is the five part of the fingerprint listed by "
				"%9/otr contexts%9 or do the command inside an OTR session "
				"private message window");
		utils_free_args(&argv, argc);
		return;
	}

	/* Trigger the forget action. */
	otr_distrust(server, target, fp, ustate);

	utils_free_args(&argv, argc);
}

/*
 * /otr info
 */
static void _cmd_info(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, const void *data)
{
	unsigned int fp_found = 0;
	char ownfp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	OtrlPrivKey *key;

	for (key = user_state_global->otr_state->privkey_root; key != NULL;
			key = key->next) {
		otrl_privkey_fingerprint(user_state_global->otr_state, ownfp,
				key->accountname, OTR_PROTOCOL_ID);
		IRSSI_NOTICE(server, target, "%B%s%n fingerprint:",
				key->accountname, ownfp);
		IRSSI_NOTICE(server, target, "%g%s%n", ownfp);
		fp_found = 1;
	}

	if (!fp_found) {
		IRSSI_NOTICE(server, target, "No key found!");
	}
}

static struct irssi_commands cmds[] = {
	{ "version", _cmd_version },
	{ "debug", _cmd_debug },
	{ "help", _cmd_help },
	{ "init", _cmd_init },
	{ "finish", _cmd_finish },
	{ "trust", _cmd_trust },
	{ "distrust", _cmd_distrust },
	{ "forget", _cmd_forget },
	{ "authabort", _cmd_authabort },
	{ "auth", _cmd_auth },
	{ "authq", _cmd_authq },
	{ "genkey", _cmd_genkey },
	{ "contexts", _cmd_contexts },
	{ "info", _cmd_info },
	{ NULL, NULL },
	{ NULL, NULL }
};

/*
 * Entry point for all other commands.
 *
 * Return TRUE if command exist and is executed else FALSE.
 */
void cmd_generic(struct otr_user_state *ustate, SERVER_REC *server,
		const char *target, char *cmd, const void *data)
{
	struct irssi_commands *commands = cmds;

	g_assert(cmd != NULL);

	do {
		if (strcmp(commands->name, cmd) == 0) {
			commands->func(ustate, server, target, data);
			return;
		}
	} while ((++commands)->name);

	IRSSI_NOTICE(server, target, "Unknown command %9%s%n", cmd);
}
