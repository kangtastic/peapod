/**
 * @file lexer.l
 * @brief Lexer for config file parser.
 */
%option nounput noinput noyywrap

%{
#include <string.h>
#include "parser.yy.h"

int linenum;
%}

digit			[0-9]
number			({digit})+
whitespace		([ \t])+
string			[a-zA-Z0-9/`~!@#$%\^&*()_\-+=:\[\]<>\.?\\]+|L?\"(\\.|[^\\"])*\"
%%

#.*$			{ /* comments */ }
{whitespace}		{ /* ignore whitespace */ }
\n			{ ++linenum; }
"{"|"}"|";"|"/"|","	{ return *yytext; }

iface			{ return T_IFACE; }
ingress			{ return T_INGRESS; }
egress			{ return T_EGRESS; }
dot1q			{ return T_DOT1Q; }

set-mac			{ return T_SET_MAC; }
set-mac-from		{ return T_SET_MAC_FROM; }
promiscuous		{ return T_PROMISCUOUS; }
filter			{ return T_FILTER; }
exec			{ return T_EXEC; }

all			{ return T_ALL; }
eap			{ return T_EAP; }
start			{ return T_START; }
logoff			{ return T_LOGOFF; }
key			{ return T_KEY; }
encapsulated-asf-alert	{ return T_ENCAPSULATED_ASF_ALERT; }
mka			{ return T_MKA; }
announcement-generic	{ return T_ANNOUNCEMENT_GENERIC; }
announcement-specific	{ return T_ANNOUNCEMENT_SPECIFIC; }
announcement-req	{ return T_ANNOUNCEMENT_REQ; }

request			{ return T_REQUEST; }
response		{ return T_RESPONSE; }
success			{ return T_SUCCESS; }
failure			{ return T_FAILURE; }

priority		{ return T_PRIORITY; }
drop-eligible		{ return T_DROP_ELIGIBLE; }
id			{ return T_ID; }
no			{ return T_NO; }

{number}		{   yylval.num = atoi(yytext); return NUMBER; }

{string}		{
				static char string[256];

				strncpy(string, yytext, sizeof(string));
				string[sizeof(string) - 1] = '\0';
				yylval.str = string;
				return STRING;
			}

.			{ return T_BAD_TOKEN; }
%%
