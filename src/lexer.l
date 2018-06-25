/**
 * @file lexer.l
 * @brief Lexer for config file parser.
 */
%option nounput noinput noyywrap

%{
#include <string.h>
#include <linux/if_ether.h>
#include "parser.yy.h"

int linenum;
%}

digit			[0-9]
number			({digit})+
hexdigit		[A-Fa-f0-9]
mac			({hexdigit}{1,2}":"){5}{hexdigit}{1,2}
whitespace		([ \t])+
string			[A-Za-z0-9/`~!@#$%\^&*()_\-+=:\[\]<>\.?\\]+|L?\"(\\.|[^\n\\"])*\"
%%

#.*$			{ /* ignore comments */ }
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

{number}		{
				yylval.num = atoi(yytext);
				return NUMBER;
			}

{mac}			{
				/* Format has been validated by lexer. */
				sscanf(yytext, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				       &yylval.mac[0], &yylval.mac[1],
				       &yylval.mac[2], &yylval.mac[3],
				       &yylval.mac[4], &yylval.mac[5]);
				return MAC;
			}

{string}		{
				static char str[4096];
				size_t len = strlen(yytext);

				if (len > (sizeof(str) - 1))
					return T_BAD_TOKEN;

				/* Dequotify strings. Conveniently, the lexer
				 * already detects unclosed double quotes.
				 */
				if (yytext[0] == '\"') {
					strncpy(str, yytext + 1, len - 2);
					str[len - 2] = '\0';
				} else {
					strcpy(str, yytext);
				}

				yylval.str = str;

				return STRING;
			}

.			{ return T_BAD_TOKEN; }
%%
