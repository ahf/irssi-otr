/*
 * Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) 2012 - David Goulet <dgoulet@ev0ke.net>
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

#include <string.h>

#include "otr.h"
#include "utils.h"

/*
 * Left trim a string.
 */
static char *ltrim(char *s)
{
	g_assert(s != NULL);

	while (isspace(*s)) {
		s++;
	}
	return s;
}

/*
 * Right trim a string.
 */
static char *rtrim(char *s)
{
	size_t len;
	char *back;

	g_assert(s != NULL);

	len = strlen(s);
	if (len == 0) {
		return s;
	}

	back = s + len;

	/* Move up to the first non whitespace character. */
	while (isspace(*--back));
	/* Remove whitespace(s) from the string. */
	*(back + 1) = '\0';

	return s;
}

/*
 * Trim whitespaces in front and back of the string.
 */
char *utils_trim_string(char *s)
{
	g_assert(s != NULL);

	return rtrim(ltrim(s));
}

/*
 * Extract question and secret for an SMP authentication.
 *
 * Return 0 and set question/secret on success. Else, return negative value and
 * params are untouched.
 */
int utils_io_extract_smp(const char *data, char **question, char **secret)
{
	unsigned int q_len, s_len;
	const char *tmp, *q_end, *q_beg, *args = data;
	char *q = NULL, *s = NULL;

	if (data == NULL || question == NULL || secret == NULL) {
		return -1;
	}

	/* Check for '[' as first char */
	q_beg = strchr(args, '[');
	if (q_beg == NULL) {
		return -1;
	}

	/*
	 * Move to "[my questions] secret"
	 *           ^
	 */
	args = q_beg + 1;

	/* Search closing bracket for the end of the question. */
	q_end = strchr(args, ']');
	if (q_end == NULL) {
		/* Malformed authq command */
		return -1;
	}

	/* Get the question length */
	q_len = (unsigned int) (q_end - args);

	/* Add 1 char for the \0 */
	q = malloc((q_len + 1) * sizeof(char));
	if (q == NULL) {
		return -1;
	}

	/* Copy question */
	strncpy(q, args, q_len);
	q[q_len] = '\0';

	/* Move to the closing bracket */
	args = q_end;

	tmp = strchr(args, ' ');
	if (tmp == NULL) {
		free(q);
		return -1;
	}

	/* Ignore the next white space */
	args = tmp + 1;

	/*
	 * "[my questions] secret"
	 *                 ^
	 */
	s_len = (unsigned int) (args - data);

	s = malloc((s_len + 1) * sizeof(char));
	if (s == NULL) {
		free(q);
		return -1;
	}

	strncpy(s, args, s_len);
	s[s_len] = '\0';

	*question = q;
	*secret = s;

	return 0;
}

/*
 * Extract the secret from an auth otr command. The secret can have more than
 * one words so this is more efficient than exploding all args and
 * concatenating them.
 *
 * Return 0 and set secret on success or else return negative value an secret
 * is untouched.
 */
int utils_auth_extract_secret(const char *_data, char **secret)
{
	int ret = -1;
	char *s, *cmd_offset = NULL, *data = NULL;

	if (_data == NULL || secret == NULL) {
		return ret;
	}

	data = strdup(_data);
	if (data == NULL) {
		return -1;
	}

	s = utils_trim_string(data);

	cmd_offset = strchr(s, ' ');
	if (cmd_offset == NULL) {
		free(data);
		return ret;
	}

	s = utils_trim_string(cmd_offset);

	*secret = strdup(s);

	free(data);
	ret = 0;
	return ret;
}

/*
 * Set _argv and _argc from the string in _data.
 *
 * On error, argv is untouched argc set to 0.
 */
void utils_explode_args(const char *_data, char ***_argv, int *_argc)
{
	int argc = 0, i = 0, have_arg = 0;
	char **argv = NULL, *c, *data = NULL, *cmd_offset;

	if (_data == NULL || _argv == NULL || _argc == NULL) {
		// We cannot set _argc here since it might be NULL.
		// FIXME: assert(_argc); before this block followed by seting it to 0.
		return;
	}

	data = strndup(_data, strlen(_data));
	if (data == NULL) {
		*_argc = argc;
		return;
	}

	c = utils_trim_string(data);

	/* Ignore first command */
	cmd_offset = strchr(c, ' ');
	if (cmd_offset == NULL) {
		*_argc = argc;
		free(data);
		return;
	}

	cmd_offset = utils_trim_string(cmd_offset);

	if (cmd_offset && strlen(cmd_offset) > 0) {
		argc++;
		have_arg = 1;
	}

	c = cmd_offset;
	while ((c = strchr(c + 1, ' '))) {
		/* Skip consecutive spaces. */
		if (*(c + 1) == ' ') {
			continue;
		}
		argc++;
		have_arg = 1;
	}

	/* No args, only spaces encountered. */
	if (!have_arg) {
		argc = 0;
		*_argc = argc;
		free(data);
		return;
	}

	argv = zmalloc(argc * sizeof(char *));
	if (argv == NULL) {
		*_argc = argc;
		free(data);
		return;
	}

	/* Ignore first command */
	c = strtok(cmd_offset, " ");
	while (c != NULL) {
		argv[i] = strdup(c);
		c = strtok(NULL, " ");
		i++;
	}

	*_argv = argv;
	*_argc = argc;
	free(data);
}

/*
 * Free an argv array. Usually, call this after using utils_explode_args.
 */
void utils_free_args(char ***argv, int argc)
{
	int i;
	char **args;

	g_assert(argv != NULL);

	/* Nothing to free. */
	if (argc == 0) {
		return;
	}

	args = *argv;

	for (i = 0; i < argc; i++) {
		if (args[i]) {
			free(args[i]);
		}
	}

	free(args);
}

/*
 * Extract otr command from an irssi command string.
 *
 * Ex: /otr auth my_secret, _cmd is set to "auth"
 */
void utils_extract_command(const char *data, char **_cmd)
{
	char *s, *cmd = NULL;

	g_assert(data != NULL);
	g_assert(_cmd != NULL);

	/* Search for the first whitespace. */
	s = strchr(data, ' ');
	if (s) {
		cmd = strndup(data, s - data);
		if (cmd == NULL) {
			return;
		}
	} else {
		cmd = strdup(data);
	}

	*_cmd = cmd;
}

/*
 * String to uppercase. Done inplace!
 */
void utils_string_to_upper(char *string)
{
	int i = 0;
	char c;

	g_assert(string != NULL);

	while (string[i]) {
		c = string[i];
		string[i] = toupper(c);
		i++;
	}
}

/*
 * Convert a fingerprint string of this format contained in parts:
 *      d81d8363 f6d6090a c2632a53 352dadfa fd296a87
 * to a privkey hash_to_human format of libotr:
 *      D81D8363 F6D6090A C2632A53 352DADFA FD296A87
 *
 * Stores the result in dst which is basically regroup the string and upper
 * case it. The dst argument must be equal or larger than
 * OTRL_PRIVKEY_FPRINT_HUMAN_LEN.
 */
void utils_hash_parts_to_readable_hash(const char **parts, char *dst)
{
	int ret;

	/* Safety net. This is a code flow error. */
	g_assert(parts != NULL && parts[0] && parts[1] && parts[2] && parts[3] && parts[4]);
	g_assert(dst != NULL);

	ret = snprintf(dst, OTRL_PRIVKEY_FPRINT_HUMAN_LEN, "%s %s %s %s %s",
			parts[0], parts[1], parts[2], parts[3], parts[4]);
	if (ret < 0) {
		return;
	}

	/* In place upper case full string. */
	utils_string_to_upper(dst);
}
