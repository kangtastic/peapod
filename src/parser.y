/**
 * @file parser.y
 * @brief Parser for config file.
 *
 * Turns a config file into a list of <tt>struct iface_t</tt> structures, so
 * that the program knows which network interfaces it should use and what it
 * should do for each interface.
 */
%define parse.error verbose
%{
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "args.h"
#include "iface.h"
#include "log.h"
#include "packet.h"
//#include "parser.h"			/* Included in packet.h */

#define u16tob_fmt	"%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c"
#define u8tob_fmt	"%c%c%c%c%c%c%c%c"
#define u16tob(u16)	(u16 & 0x8000 ? '1' : '0'), (u16 & 0x4000 ? '1' : '0'), \
			(u16 & 0x2000 ? '1' : '0'), (u16 & 0x1000 ? '1' : '0'), \
			(u16 & 0x800 ? '1' : '0'), (u16 & 0x400 ? '1' : '0'), \
			(u16 & 0x200 ? '1' : '0'), (u16 & 0x100 ? '1' : '0'), \
			(u16 & 0x80 ? '1' : '0'), (u16 & 0x40 ? '1' : '0'), \
			(u16 & 0x20 ? '1' : '0'), (u16 & 0x10 ? '1' : '0'), \
			(u16 & 0x8 ? '1' : '0'), (u16 & 0x4 ? '1' : '0'), \
			(u16 & 0x2 ? '1' : '0'), (u16 & 0x1 ? '1' : '0')
#define u8tob(u8)	(u8 & 0x80 ? '1' : '0'), (u8 & 0x40 ? '1' : '0'), \
			(u8 & 0x20 ? '1' : '0'), (u8 & 0x10 ? '1' : '0'), \
			(u8 & 0x8 ? '1' : '0'), (u8 & 0x4 ? '1' : '0'), \
			(u8 & 0x2 ? '1' : '0'), (u8 & 0x1 ? '1' : '0')

/* begin: magic flex lines, for to make not angry compiler */
#define YY_DECL
extern int yylex(void);
int yyparse(void);
extern FILE *yyin;
extern void yyset_in(FILE *_in_str);
extern int yylex_destroy(void);
/* end: magic flex lines */

static void allocate(void **ptr, size_t size);
static inline void set_reset(void **dest, void **src);
static char *dequotify(const char *in);
static char *dequotify_path(const char *in);

static void print_filter(struct filter_t *filter);
static void print_action(struct action_t *action);
static void abort_parser(void);
static void free_iface(struct iface_t *iface);
static void free_ingress(struct ingress_t *ingress);
static void free_egress(struct egress_t *egress);
static void free_action(struct action_t *action);

static char *conffile = NULL;

static struct iface_t *ifaces = NULL;
static struct iface_t *iface = NULL;
static struct ingress_t *ingress = NULL;
static struct egress_t *egress = NULL;
static struct tci_t *tci = NULL;
static struct filter_t *filter = NULL;
static struct action_t *action = NULL;

extern int linenum;		/* lexer.l: line number in config file */

struct iface_t *parse_config(const char *path)
{
	linenum = 1;

	conffile = strdup(path);
	FILE *fd = fopen(conffile, "r");
	if (fd == NULL) {
		eerr("cannot open config file '%s': %s", conffile);
		exit(EXIT_FAILURE);
	}

	yyset_in(fd);

	if (yyparse() != 0)
		abort_parser();

	yylex_destroy();
	fclose(fd);

	int count = 0;
	for (struct iface_t *i = ifaces; i != NULL; i = i->next) {
		++count;

		/* check that set-mac-from named a configured interface */
		if (i->set_mac_from == 0)
			continue;

		int found = 0;
		for (struct iface_t *j = ifaces; j != NULL; j = j->next) {
			if (i->set_mac_from == j->index) {
				found = 1;
				break;
			}
		}

		if (found == 0) {
			err("set-mac-from unconfigured interface on '%s'",
			    i->name);
			abort_parser();
		}
	}

	if (count < 2) {
		err("at least two interfaces must be defined in config file '%s'",
		    conffile);
		abort_parser();
	}

	notice("loaded config from '%s'", conffile);

	return ifaces;
}

static void allocate(void **ptr, size_t size)
{
	if (*ptr == NULL && (*ptr = calloc(1, size)) == NULL) {
		ecrit("cannot allocate memory: %s");
		abort_parser();
	}
}

static inline void set_reset(void **dest, void **src)
{
	if (*src != NULL) {
		*dest = *src;
		*src = NULL;
	}
}

/* caller responsible for free(3)ing the result */
static char *dequotify(const char *in)
{
	char *ret;
	if (in[0] == '\"')	/* lexer already detects unclosed quotes */
		ret = strndup(in + 1, strlen(in) - 2);
	else
		ret = strdup(in);

	if (ret == NULL) {
		ecrit("cannot allocate memory: %s");
		abort_parser();
	}
	return ret;
}

/* caller responsible for free(3)ing the result */
static char *dequotify_path(const char *path)
{
	char *dequotified = dequotify(path);
	char *ret = args_canonpath(dequotified, 0);

	if (ret == NULL) {
		eerr("cannot use script '%s' (line %d): %s",
		     dequotified, linenum);
		abort_parser();
	}

	if (strcmp(dequotified, ret) != 0) {
		err("path to script '%s' must be absolute and canonical (line %d)",
		    dequotified, linenum);
		abort_parser();
	}

	free(dequotified);

	struct stat sb;
	if (stat(ret, &sb) == -1) {
		eerr("cannot get file status for script '%s' (line %d): %s",
		     ret, linenum);
		abort_parser();
	}

	mode_t mode;
	if (sb.st_uid == geteuid())
		mode = S_IXUSR;
	else if (sb.st_gid == getegid())
		mode = S_IXGRP;
	else
		mode = S_IXOTH;

	if ((sb.st_mode & mode) == 0) {
		err("script '%s' is not executable for effective user %u",
		    ret, geteuid());
		abort_parser();
	}

	return ret;
}

void parser_print_ifaces(struct iface_t *list)
{
	if (list == NULL) {
		err("no interface list was passed");
		return;
	}

	debuglow("\tiface: %p {", list);
	debuglow("\t  name='%s'", list->name);
	debuglow("\t  index=%u", list->index);
	debuglow("\t  mtu=%d", list->mtu);
	debuglow("\t  skt=%d", list->skt);
	debuglow("\t  recv_ctr=%d", list->recv_ctr);
	debuglow("\t  send_ctr=%d", list->send_ctr);
	if (list->ingress != NULL) {
		struct ingress_t *ingress = list->ingress;
		debuglow("\t  ingress: %p {", ingress);
		print_action(ingress->action);
		print_filter(ingress->filter);
		debuglow("\t  }");
	} else {
		debuglow("\t  ingress: %p", list->ingress);
	}
	if (list->egress != NULL) {
		struct egress_t *egress = list->egress;
		debuglow("\t  egress: %p {", egress);
		if (egress->tci != NULL) {
			struct tci_t *tci = egress->tci;
			debuglow("\t    tci: %p {", tci);
			debuglow("\t      pcp=0x%.02x", tci->pcp);
			debuglow("\t      dei=0x%.02x", tci->dei);
			debuglow("\t      vid=0x%.04x", tci->vid);
			debuglow("\t    }");
		} else {
			debuglow("\t    tci: %p", egress->tci);
		}
		print_filter(egress->filter);
		print_action(egress->action);
		debuglow("\t  }");
	} else {
		debuglow("\t  egress: %p", list->egress);
	}
	debuglow("\t  promisc=%u", list->promisc);
	debuglow("\t  set_mac='%s',0x%.02x",
		 iface_strmac(list->set_mac),
		 list->set_mac[ETH_ALEN]);
	debuglow("\t  set_mac_from=%u", list->set_mac_from);
	debuglow("\t  next: %p", list->next);
	debuglow("\t}");

	if (list->next != NULL)
		parser_print_ifaces(list->next);
}

static void print_filter(struct filter_t *filter)
{
	if (filter == NULL) {
		debuglow("\t    filter: %p", filter);
		return;
	}

	debuglow("\t    filter: %p {", filter);
	debuglow("\t      type=0b" u16tob_fmt, u16tob(filter->type));
	debuglow("\t      code=0b" u8tob_fmt, u8tob(filter->code));
	debuglow("\t    }");
}

static void print_action(struct action_t *action)
{
	if (action == NULL) {
		debuglow("\t    action: %p", action);
		return;
	}

	debuglow("\t    action: %p {", action);
	debuglow("\t      type: %p {", action->type);
	for (int i = EAPOL_EAP; i <= EAPOL_ANNOUNCEMENT_REQ; ++i)
		debuglow("\t        '%s',", action->type[i]);
	debuglow("\t      }");

	debuglow("\t      code: %p {", action->code);
	for (int i = EAP_CODE_REQUEST; i <= EAP_CODE_FAILURE; ++i)
		debuglow("\t        '%s',", action->code[i]);
	debuglow("\t      }");
	debuglow("\t    }");
}

static void abort_parser(void)
{
	err("cannot parse config file '%s'", conffile);
	free_ingress(ingress);
	free_egress(egress);
	free(tci);
	free(filter);
	free_action(action);
	free_iface(iface);
	free_iface(ifaces);
	free(conffile);
	exit(EXIT_FAILURE);
}

static void free_iface(struct iface_t *iface)
{
	if (iface == NULL)
		return;
	free_ingress(iface->ingress);
	free_egress(iface->egress);
	free_iface(iface->next);
	free(iface);
}

static void free_ingress(struct ingress_t *ingress)
{
	if (ingress == NULL)
		return;
	free(ingress->filter);
	free_action(ingress->action);
}

static void free_egress(struct egress_t *egress)
{
	if (egress == NULL)
		return;
	free(egress->tci);
	free(egress->filter);
	free_action(egress->action);
}

static void free_action(struct action_t *action)
{
	if (action == NULL)
		return;
	for (int i = 0; i < 5; ++i)
		free(action->type[i]);
	for (int i = 1; i < 5; ++i)
		free(action->code[i]);
}

static void yyerror(const char *str)
{
	err("parser error (line %d): %s", linenum, str);
}


%}

%token	<str>	STRING
%token	<num>	NUMBER

%token		T_IFACE

%token		T_INGRESS
%token		T_EGRESS
%token		T_DOT1Q

%token		T_SET_MAC
%token		T_SET_MAC_FROM
%token		T_PROMISCUOUS
%token		T_FILTER
%token		T_EXEC

%token		T_ALL
%token		T_EAP
%token		T_START
%token		T_LOGOFF
%token		T_KEY
%token		T_ENCAPSULATED_ASF_ALERT
%token		T_MKA
%token		T_ANNOUNCEMENT_GENERIC
%token		T_ANNOUNCEMENT_SPECIFIC
%token		T_ANNOUNCEMENT_REQ

%token		T_REQUEST
%token		T_RESPONSE
%token		T_SUCCESS
%token		T_FAILURE

%token		T_PRIORITY
%token		T_DROP_ELIGIBLE
%token		T_ID
%token		T_NO

%token		T_BAD_TOKEN

%union {
	unsigned num;
	char *str;
};

%%
grammar		: grammar ifacedef
		| ifacedef
		;

ifacedef	: ifacehead '{' ifaceparams '}' ';'
		{
			if (iface->set_mac_from != 0) {
				if (iface->set_mac[ETH_ALEN] == IFACE_SET_MAC) {
					err("both set-mac and set-mac-from on '%s' (line %d)",
					    iface->name, linenum);
					abort_parser();
				}

				if (iface->index == iface->set_mac_from) {
					err("set-mac-from self on '%s' (line %d)",
					    iface->name, linenum);
					abort_parser();
				}
			}

			set_reset((void *)&iface->ingress, (void *)&ingress);
			set_reset((void *)&iface->egress, (void *)&egress);

			iface->next = ifaces;

			debuglow("got iface definition for '%s' %p",
				 iface->name, iface);
			set_reset((void *)&ifaces, (void *)&iface);
		}
		| ifacehead ';' /* empty params */
		{
			iface->next = ifaces;

			debuglow("got iface definition for '%s' %p",
				 iface->name, iface);
			set_reset((void *)&ifaces, (void *)&iface);
		}
		;

ifacehead	: T_IFACE STRING
		{
			char *tok2 = dequotify($2);
			if (strlen(tok2) > IFNAMSIZ - 1) {
				err("interface name '%s' too long (line %d)",
				    tok2, linenum);
				free(tok2);
				abort_parser();
			}

			unsigned index = if_nametoindex(tok2);
			if (index == 0) {
				eerr("no interface '%s' found (line %d): %s",
				     tok2, linenum);
				free(tok2);
				abort_parser();
			}

			for (struct iface_t *i = ifaces;
			     i != NULL; i = i->next) {
				if (strcmp(tok2, i->name) == 0) {
					err("interface '%s' already defined (line %d)",
					    tok2, linenum);
					free(tok2);
					abort_parser();
				}
			}

			allocate((void *)&iface, sizeof(struct iface_t));

			strncpy(iface->name, tok2, IFNAMSIZ);
			iface->index = index;

			free(tok2);
			debuglow("iface=%p, iface->name=%s, iface->index=%d",
				 iface, iface->name, iface->index);
		}
		;

ifaceparams	: ifaceparams ifaceparam
		| /* empty */
		;

ifaceparam	: ingressdef
		| egressdef
		| promiscuousdef
		| setmacdef
		| setmacfromdef
		;

ingressdef	: ingresshead '{' ingressparams '}' ';'
		{
			set_reset((void *)&ingress->filter, (void *)&filter);
			set_reset((void *)&ingress->action, (void *)&action);

			debuglow("got ingress definition %p", ingress);
		}
		;

ingresshead	: T_INGRESS
		{
			if (ingress != NULL) {
				err("ingress twice in same iface stanza (line %d)",
				    linenum);
				abort_parser();
			}

			allocate((void *)&ingress, sizeof(struct ingress_t));
			debuglow("ingress=%p", ingress);
		}
		;

ingressparams	: ingressparams ingressparam
		| ingressparam
		;

ingressparam	: execdef
		| filterdef
		;


filterdef	: filterhead filtertypes ';'
		{
			debuglow("got filter definition %p", filter);
		}
		;

filterhead	: T_FILTER
		{
			allocate((void *)&filter, sizeof(struct filter_t));
			debuglow("filter=%p", filter);
		}
		;

filtertypes	: filtertypes ',' filtertype
		| filtertype
		;

filtertype	: T_ALL
		{
			/*
			for (int i = EAPOL_EAP;
			     i <= EAPOL_ANNOUNCEMENT_REQ;
			     ++i)
				filter->type |= 1 << i;
			*/
			filter->type = 0x1ff;
		}
		| T_EAP
		{
			filter->type |= 1 << EAPOL_EAP;
		}
		| T_START
		{
			filter->type |= 1 << EAPOL_START;
		}
		| T_LOGOFF
		{
			filter->type |= 1 << EAPOL_LOGOFF;
		}
		| T_KEY
		{
			filter->type |= 1 << EAPOL_KEY;
		}
		| T_ENCAPSULATED_ASF_ALERT
		{
			filter->type |= 1 << EAPOL_ENCAPSULATED_ASF_ALERT;
		}
		| T_MKA
		{
			filter->type |= 1 << EAPOL_MKA;
		}
		| T_ANNOUNCEMENT_GENERIC
		{
			filter->type |= 1 << EAPOL_ANNOUNCEMENT_GENERIC;
		}
		| T_ANNOUNCEMENT_SPECIFIC
		{
			filter->type |= 1 << EAPOL_ANNOUNCEMENT_SPECIFIC;
		}
		| T_ANNOUNCEMENT_REQ
		{
			filter->type |= 1 << EAPOL_ANNOUNCEMENT_REQ;
		}
		| T_REQUEST
		{
			filter->code |= 1 << EAP_CODE_REQUEST;
		}
		| T_RESPONSE
		{
			filter->code |= 1 << EAP_CODE_RESPONSE;
		}
		| T_SUCCESS
		{
			filter->code |= 1 << EAP_CODE_SUCCESS;
		}
		| T_FAILURE
		{
			filter->code |= 1 << EAP_CODE_FAILURE;
		}
		;

execdef		: exechead execparam ';'
		{
			debuglow("got action definition %p", action);
		}
		;

exechead	: T_EXEC
		{
			allocate((void *)&action, sizeof(struct action_t));
			debuglow("action=%p", action);
		}
		;

execparam	: T_ALL STRING
		{
			for (int i = EAPOL_EAP;
			     i <= EAPOL_ANNOUNCEMENT_REQ;
			     ++i)
				action->type[i] = dequotify_path($2);
		}
		| T_EAP STRING
		{
			action->type[EAPOL_EAP] = dequotify_path($2);
		}
		| T_START STRING
		{
			action->type[EAPOL_START] = dequotify_path($2);
		}
		| T_LOGOFF STRING
		{
			action->type[EAPOL_LOGOFF] = dequotify_path($2);
		}
		| T_KEY STRING
		{
			action->type[EAPOL_KEY] = dequotify_path($2);
		}
		| T_ENCAPSULATED_ASF_ALERT STRING
		{
			action->type[EAPOL_ENCAPSULATED_ASF_ALERT] = dequotify_path($2);
		}
		| T_MKA STRING
		{
			action->type[EAPOL_MKA] = dequotify_path($2);
		}
		| T_ANNOUNCEMENT_GENERIC STRING
		{
			action->type[EAPOL_ANNOUNCEMENT_GENERIC] = dequotify_path($2);
		}
		| T_ANNOUNCEMENT_SPECIFIC STRING
		{
			action->type[EAPOL_ANNOUNCEMENT_SPECIFIC] = dequotify_path($2);
		}
		| T_ANNOUNCEMENT_REQ STRING
		{
			action->type[EAPOL_ANNOUNCEMENT_REQ] = dequotify_path($2);
		}
		| T_REQUEST STRING
		{
			action->code[EAP_CODE_REQUEST] = dequotify_path($2);
		}
		| T_RESPONSE STRING
		{
			action->code[EAP_CODE_RESPONSE] = dequotify_path($2);
		}
		| T_SUCCESS STRING
		{
			action->code[EAP_CODE_SUCCESS] = dequotify_path($2);
		}
		| T_FAILURE STRING
		{
			action->code[EAP_CODE_FAILURE] = dequotify_path($2);
		}
		;

egressdef	: T_EGRESS '{' egressparams '}' ';'
		{
			if (egress != NULL) {
				err("egress twice in same iface stanza (line %d)",
				    linenum);
				abort_parser();
			}

			allocate((void *)&egress, sizeof(struct egress_t));

			set_reset((void *)&egress->tci, (void *)&tci);
			set_reset((void *)&egress->filter, (void *)&filter);
			set_reset((void *)&egress->action, (void *)&action);

			debuglow("got egress definition %p", egress);
		}
		;

egressparams	: egressparams egressparam
		| egressparam
		;

egressparam	: filterdef
		| execdef
		| dot1qdef
		;

dot1qdef	: dot1qhead '{' dot1qparams '}' ';'
		{
			debuglow("got dot1q definition %p", tci);
		}
		| T_NO T_DOT1Q ';'
		{
			if (tci != NULL) {
				err("dot1q twice in same egress stanza (line %d)",
				    linenum);
				abort_parser();
			}
			allocate((void *)&tci, sizeof(struct tci_t));
			memset(tci, TCI_NO_DOT1Q, sizeof(struct tci_t));
			debuglow("got dot1q definition %p", tci);
		}
		;

dot1qhead	: T_DOT1Q
		{
			if (tci != NULL) {
				err("dot1q twice in same egress stanza (line %d)",
				    linenum);
				abort_parser();
			}
			allocate((void *)&tci, sizeof(struct tci_t));
			memset(tci, TCI_UNTOUCHED, sizeof(struct tci_t));
			debuglow("dot1q=%p", tci);
		}
		;

dot1qparams	: dot1qparams dot1qparam
		| dot1qparam
		;

dot1qparam	: prioritydef
		| dropeligibledef
		| iddef
		;

prioritydef	: T_PRIORITY NUMBER ';'
		{
			if ($2 > 7) {
				err("dot1q priority not 0-7 (line %d)",
				    linenum);
				abort_parser();
			}
			tci->pcp = $2;
		}
		;

dropeligibledef	: T_DROP_ELIGIBLE NUMBER ';'
		{
			if ($2 > 1) {
				err("dot1q drop-eligible not 0-1 (line %d)",
				    linenum);
				abort_parser();
			}
			tci->dei = $2;
		}
		;

iddef		: T_ID NUMBER ';'
		{
			if ($2 > 4094) {
				err("dot1q id not 0-4094 (line %d)",
				    linenum);
				abort_parser();
			}
			tci->vid = $2;
		}
		;

promiscuousdef	: T_PROMISCUOUS ';'
		{
			iface->promisc = 1;
		}
		;

setmacdef	: T_SET_MAC STRING ';'
		{
			char *tok2 = dequotify($2);

			regex_t rgx;
			char *pat = "^([A-Fa-f0-9]{1,2}:){5}[A-Fa-f0-9]{1,2}$";
			int rv;
			char *remsg = NULL;	/* regex error message buffer */
			size_t resiz;

			u_char mac[ETH_ALEN];

			rv = regcomp(&rgx, pat, REG_EXTENDED);
			if (rv != 0) {
				resiz = regerror(rv, &rgx, NULL, 0);
				allocate((void *)&remsg, resiz);
				regerror(rv, &rgx, remsg, resiz);

				err("cannot compile regex: %s", remsg);
				free(remsg);
				free(tok2);
				abort_parser();
			}

			rv = regexec(&rgx, tok2, 0, NULL, 0);
			if (rv == 0) {
				/* format has been validated by regex */
				sscanf(tok2, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				       &mac[0], &mac[1], &mac[2],
				       &mac[3], &mac[4], &mac[5]);

				if ((mac[0] & 0xfe) == 1) {
					err("'%s' is a multicast MAC address (line %d)",
					    tok2, linenum);
					regfree(&rgx);
					free(tok2);
					abort_parser();
				}

				memcpy(iface->set_mac, mac, ETH_ALEN);
				iface->set_mac[ETH_ALEN] = IFACE_SET_MAC;
			} else if (rv == REG_NOMATCH) {
				err("'%s' is not a MAC address (line %d)",
				    tok2, linenum);
				regfree(&rgx);
				free(tok2);
				abort_parser();
			} else {
				/* might not ever get here on Linux,
				 * but might also be more POSIXly correct
				 */
				resiz = regerror(rv, &rgx, NULL, 0);
				allocate((void *)&remsg, resiz);
				regerror(rv, &rgx, remsg, resiz);

				err("cannot check for regex match: %s", remsg);
				free(remsg);
				free(tok2);
				abort_parser();
			}

			regfree(&rgx);
			free(tok2);
		}
		;

setmacfromdef	: T_SET_MAC_FROM STRING ';'
		{
			char *tok2 = dequotify($2);
			if (strlen(tok2) > IFNAMSIZ - 1) {
				err("interface name '%s' too long (line %d)",
				    tok2, linenum);
				free(tok2);
				abort_parser();
			}

			unsigned index = if_nametoindex(tok2);
			if (index == 0) {
				eerr("no interface '%s' found (line %d): %s",
				     tok2, linenum);
				free(tok2);
				abort_parser();
			}

			iface->set_mac_from = index;

			free(tok2);
		}
		;
