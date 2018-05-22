%define parse.error verbose
%{
#include "includes.h"

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
static struct if_nameindex *ifni = NULL;

static struct iface_t *ifaces = NULL;
static struct iface_t *iface = NULL;
static struct ingress_t *ingress = NULL;
static struct egress_t *egress = NULL;
static struct tci_t *tci = NULL;
static struct filter_t *filter = NULL;
static struct action_t *action = NULL;

extern int linenum;			/* lexer.l: line number in conffile */

struct iface_t *parse_config(const char *path)
{
	linenum = 1;

	ifni = if_nameindex();
	if (ifni == NULL) {
		eerr("cannot obtain interface information from kernel: %s");
		exit(EXIT_FAILURE);
	}

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

	if_freenameindex(ifni);

	if (iface_count(ifaces) < 2) {
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

/* caller responsible for free()ing the result */
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

/* caller responsible for free()ing the result */
static char *dequotify_path(const char *path)
{
	if (path[0] != '/') {
		if (path[0] != '"' && path[1] != '/') {
			err("script filenames must be absolute paths (line %d)",
			    linenum);
			abort_parser();
		}
	}

	char *dequotified = dequotify(path);

	if (access(dequotified, X_OK) == -1) {
		eerr("script '%s' is not executable (line %d): %s",
		     dequotified, linenum);
		abort_parser();
	}

	char *ret = args_canonpath(dequotified, 0);
	free(dequotified);

	return ret;
}

void parser_print_ifaces(struct iface_t *list)
{
	if (list == NULL) {
		err("no interface list was passed");
		return;
	}

	debuglow("\tiface object: %p {", list);
	debuglow("\t  name=\"%s\"", list->name);
	debuglow("\t  index=%d", list->index);
	debuglow("\t  mtu=%d", list->mtu);
	debuglow("\t  skt=%d", list->skt);
	if (list->ingress != NULL) {
		struct ingress_t *ingress = list->ingress;
		debuglow("\t  ingress: %p {", ingress);
		if (ingress->set_mac[0] != '\0')
			debuglow("\t    set_mac=\"%s\"", ingress->set_mac);
		else
			debuglow("\t    set_mac=NULL");

		if (ingress->filter != NULL)
			print_filter(ingress->filter);
		else
			debuglow("\t    filter=NULL");

		if (ingress->action != NULL)
			print_action(ingress->action);
		else
			debuglow("\t    action=NULL");
		debuglow("\t  }");
	} else {
		debuglow("\t  ingress=NULL");
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
			debuglow("\t    tci=NULL");
		}
		if (egress->filter != NULL)
			print_filter(egress->filter);
		if (egress->action != NULL)
			print_action(egress->action);
		debuglow("\t  }");
	} else {
		debuglow("\t  egress=NULL");
	}
	debuglow("\t  promisc=%u", list->promisc);
	if (list->set_mac[ETH_ALEN] == IFACE_SET_MAC)
		debuglow("\t  set_mac='%s'", iface_strmac(list->set_mac));
	else
		debuglow("\t  set_mac=none");

	if (list->next != NULL)
		debuglow("\t  next: %p", list->next);
	else
		debuglow("\t  next=NULL");
	debuglow("\t}");

	if (list->next != NULL)
		parser_print_ifaces(list->next);
}

static void print_filter(struct filter_t *filter)
{
	debuglow("\t    filter: %p {", filter);
	debuglow("\t      frame=0b" u8tob_fmt, u8tob(filter->frame));
	debuglow("\t      packet=0b" u8tob_fmt, u8tob(filter->packet));
	debuglow("\t    }");
}

static void print_action(struct action_t *action)
{
	debuglow("\t    action: %p {", action);
	debuglow("\t      frame: %p {", action->frame);
	for (int i = 0; i < 5; i++)
		if (action->frame[i])
			debuglow("\t        \"%s\",", action->frame[i]);
		else
			debuglow("\t        NULL,");
	debuglow("\t      }");

	debuglow("\t      packet: %p {", action->packet);
	for (int i = 0; i < 5; i++)
		if (action->packet[i])
			debuglow("\t        \"%s\",", action->packet[i]);
		else
			debuglow("\t        NULL,");
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
	if_freenameindex(ifni);
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
	for (int i = 0; i < 5; i++)
		free(action->frame[i]);
	for (int i = 1; i < 5; i++)
		free(action->packet[i]);
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
%token		T_PROMISCUOUS
%token		T_FILTER
%token		T_EXEC

%token		T_ALL
%token		T_PACKET
%token		T_START
%token		T_LOGOFF
%token		T_KEY
%token		T_ENCAP_ASF_ALERT

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
			/* check for two set-mac declarations */
			if (iface->set_mac[ETH_ALEN] == IFACE_SET_MAC &&
			    ingress != NULL &&
			    ingress->set_mac[0] != '\0') {
				err("set-mac twice on interface '%s' (line %d)",
				    iface->name, linenum);
				abort_parser();
			}
			set_reset((void*)&iface->ingress, (void*)&ingress);
			set_reset((void*)&iface->egress, (void*)&egress);
			iface->next = ifaces;
			debuglow("got iface definition for '%s'", iface->name);
			set_reset((void*)&ifaces, (void*)&iface);
		}
		| ifacehead ';' /* empty params */
		{
			iface->next = ifaces;
			debuglow("got iface definition for '%s'", iface->name);
			set_reset((void*)&ifaces, (void*)&iface);
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

			int index = 0;
			int found = 0;
			for (struct if_nameindex *i = ifni;
			     i->if_name != NULL; i++) {
				if (strcmp(i->if_name, tok2) == 0) {
					index = i->if_index;
					found = 1;
					break;
				}
			}
			if (found == 0) {
				err("no interface '%s' found (line %d)",
				    tok2, linenum);
				free(tok2);
				abort_parser();
			}

			for (struct iface_t *i = ifaces;
			     i != NULL;
			     i = i->next) {
				if (strcmp(tok2, i->name) == 0) {
					err("interface '%s' already defined (line %d)",
					    tok2, linenum);
					free(tok2);
					abort_parser();
				}
			}

			allocate((void*)&iface, sizeof(struct iface_t));

			strncpy(iface->name, tok2, IFNAMSIZ);
			iface->index = index;

			free(tok2);
			debuglow("iface=0x%p, iface->name=%s, iface->index=%d",
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
		;

ingressdef	: ingresshead '{' ingressparams '}' ';'
		{
			set_reset((void*)&ingress->filter, (void*)&filter);
			set_reset((void*)&ingress->action, (void*)&action);

			debuglow("got definition of ingress object at 0x%p",
				 ingress);
		}
		;

ingresshead	: T_INGRESS
		{
			if (ingress != NULL) {
				err("ingress twice in same iface stanza (line %d)",
				    linenum);
				abort_parser();
			}

			allocate((void*)&ingress, sizeof(struct ingress_t));
			debuglow("ingress=0x%p", ingress);
		}
		;

ingressparams	: ingressparams ingressparam
		| ingressparam
		;

ingressparam	: insetmacdef
		| filterdef
		| execdef
		;

insetmacdef	: T_SET_MAC STRING ';'
		{
			char *tok2 = dequotify($2);
			if (strlen(tok2) > IFNAMSIZ - 1) {
				err("interface name '%s' too long (line %d)",
				    tok2, linenum);
				free(tok2);
				abort_parser();
			}

			int found = 0;
			for (struct if_nameindex *i = ifni;
			     i->if_name != NULL; i++) {
				if (strcmp(i->if_name, tok2) == 0) {
					found = 1;
					break;
				}
			}

			if (found == 0) {
				err("no interface '%s' found (line %d)",
				    tok2, linenum);
				free(tok2);
				abort_parser();
			}

			strncpy(ingress->set_mac, tok2, IFNAMSIZ);
			free(tok2);
		}
		;

filterdef	: filterhead filtertypes ';'
		{
			debuglow("got definition of filter object at 0x%p",
				 filter);
		}
		;

filterhead	: T_FILTER
		{
			allocate((void*)&filter, sizeof(struct filter_t));
			debuglow("filter=0x%p", filter);
		}
		;

filtertypes	: filtertypes ',' filtertype
		| filtertype
		;

filtertype	: T_ALL
		{
			for (int i = EAPOL_EAP_PACKET;		/* 0 */
			     i <= EAPOL_ENCAP_ASF_ALERT;	/* 4 */
			     i++)
				filter->frame |= 1 << i;
		}
		| T_PACKET
		{
			filter->frame |= 1 << EAPOL_EAP_PACKET;
		}
		| T_START
		{
			filter->frame |= 1 << EAPOL_START;
		}
		| T_LOGOFF
		{
			filter->frame |= 1 << EAPOL_LOGOFF;
		}
		| T_KEY
		{
			filter->frame |= 1 << EAPOL_KEY;
		}
		| T_ENCAP_ASF_ALERT
		{
			filter->frame |= 1 << EAPOL_ENCAP_ASF_ALERT;
		}
		| T_REQUEST
		{
			filter->packet |= 1 << EAP_PACKET_REQUEST;
		}
		| T_RESPONSE
		{
			filter->packet |= 1 << EAP_PACKET_RESPONSE;
		}
		| T_SUCCESS
		{
			filter->packet |= 1 << EAP_PACKET_SUCCESS;
		}
		| T_FAILURE
		{
			filter->packet |= 1 << EAP_PACKET_FAILURE;
		}
		;

execdef		: exechead execparam ';'
		{
			debuglow("got definition of action object at 0x%p",
				 action);
		}
		;

exechead	: T_EXEC
		{
			allocate((void*)&action, sizeof(struct action_t));
			debuglow("action=0x%p", action);
		}
		;

execparam	: T_ALL STRING
		{
			for (int i = EAPOL_EAP_PACKET;
			     i <= EAPOL_ENCAP_ASF_ALERT;
			     i++)
				action->frame[i] = dequotify_path($2);
		}
		| T_PACKET STRING
		{
			action->frame[EAPOL_EAP_PACKET] = dequotify_path($2);
		}
		| T_START STRING
		{
			action->frame[EAPOL_START] = dequotify_path($2);
		}
		| T_LOGOFF STRING
		{
			action->frame[EAPOL_LOGOFF] = dequotify_path($2);
		}
		| T_KEY STRING
		{
			action->frame[EAPOL_KEY] = dequotify_path($2);
		}
		| T_ENCAP_ASF_ALERT STRING
		{
			action->frame[EAPOL_ENCAP_ASF_ALERT] = dequotify_path($2);
		}
		| T_REQUEST STRING
		{
			action->packet[EAP_PACKET_REQUEST] = dequotify_path($2);
		}
		| T_RESPONSE STRING
		{
			action->packet[EAP_PACKET_RESPONSE] = dequotify_path($2);
		}
		| T_SUCCESS STRING
		{
			action->packet[EAP_PACKET_SUCCESS] = dequotify_path($2);
		}
		| T_FAILURE STRING
		{
			action->packet[EAP_PACKET_FAILURE] = dequotify_path($2);
		}
		;

egressdef	: T_EGRESS '{' egressparams '}' ';'
		{
			if (egress != NULL) {
				err("egress twice in same iface stanza (line %d)",
				    linenum);
				abort_parser();
			}

			allocate((void*)&egress, sizeof(struct egress_t));

			set_reset((void*)&egress->tci, (void*)&tci);
			set_reset((void*)&egress->filter, (void*)&filter);
			set_reset((void*)&egress->action, (void*)&action);

			debuglow("got definition of egress object at 0x%p",
				 egress);
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
			debuglow("got dot1q definition");
		}
		| T_NO T_DOT1Q ';'
		{
			if (tci != NULL) {
				err("dot1q twice in same egress stanza (line %d)",
				    linenum);
				abort_parser();
			}
			allocate((void*)&tci, sizeof(struct tci_t));
			memset(tci, TCI_NO_DOT1Q, sizeof(struct tci_t));
			debuglow("got negative dot1q definition");
		}
		;

dot1qhead	: T_DOT1Q
		{
			if (tci != NULL) {
				lerr("dot1q twice in same egress stanza (line %d)",
				    linenum);
				abort_parser();
			}
			allocate((void*)&tci, sizeof(struct tci_t));
			memset(tci, TCI_UNTOUCHED, sizeof(struct tci_t));
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
				err("invalid VLAN priority (line %d)", linenum);
				abort_parser();
			}
			tci->pcp = $2;
		}
		;

dropeligibledef	: T_DROP_ELIGIBLE ';'
		{
			tci->dei = 1;
		}
		;

iddef		: T_ID NUMBER ';'
		{
			if ($2 > 4094) {
				err("invalid VLAN ID (line %d)", linenum);
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
			u_char mac[ETH_ALEN];

			if (regcomp(&rgx, pat, REG_EXTENDED) != 0) {
				err("cannot compile regex");
				free(tok2);
				abort_parser();
			}

			if (regexec(&rgx, tok2, 0, NULL, 0) == 0) {
				/* Format has been validated by regex */
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
			} else {
				err("'%s' is not a MAC address (line %d)",
				    tok2, linenum);
				regfree(&rgx);
				free(tok2);
				abort_parser();
			}

			regfree(&rgx);
			free(tok2);
		}
		;
