/*
 * Password fetcher function. Just tampers with the console to make password
 * not echo back. Of course only if termios is found.
 *
 * Copyright (c) 2004 Aki Tossavainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */
#include "eics.h"

/* Gets a password */
int
eics_get_cb (const char *query, char *pass, int maxlen)
{
  /* This is only done if termios present */
#ifdef HAVE_TERMIOS_H
  struct termios term;
  FILE *fin;
  char *tty;
  /* We try to get the filedescriptor for fd 0 */
  tty = malloc (sizeof (char) * 513);
  memset (tty, 0, sizeof (char) * 513);
  if (readlink ("/proc/self/fd/0", tty, 512) < 0)
    {
      fin = stdin;
    }
  else
    {
      if (!(fin = fopen (tty, "a+")))
	{
	  free (tty);
	  return 0;
	}
    }
  free (tty);
  /* Setup terminal for non-echo */
  tcgetattr (fileno (fin), &term);
  term.c_lflag &= ~ECHO;
  tcsetattr (fileno (fin), TCSANOW, &term);
  /* Get the password */
  if (fin != stdin)
    {
      fprintf (fin, "%s(max. %d letters): ", query, maxlen);
    }
  else
    {
      fprintf (stdout, "%s(max. %d letters): ", query, maxlen);
    }
  fflush (NULL);
#else
  /* NOTE NOTE NOTE THIS IS NOT CONTINUAM OF THE ABOVE
   * INSTEAD THIS CODE REPLACES THE ABOVE
   */
  fprintf (stdout, "%s(max. %d letters): ", query, maxlen);
  fflush (NULL);
#endif
  /* clear password */
  memset (pass, 0, sizeof (char) * (maxlen + 1));
#ifdef HAVE_TERMIOS_H
  /* get password */
  fgets (pass, maxlen, fin);
  /* restore console */
  tcgetattr (fileno (fin), &term);
  term.c_lflag |= ECHO;
  tcsetattr (fileno (fin), TCSANOW, &term);
  fputs ("\n", stdout);
  if (fin != stdin)
    fclose (fin);
#else
  /* Just get the password and do nothing , no termios */
  fgets (pass, maxlen, stdin);
#endif
  return strlen (pass);
}

/* This compares two passwords to ensure same was given */
int
get_compare_cb (char **p1, char **p2, int maxlen)
{
  *p1 = malloc (sizeof (char) * (maxlen + 1));
  *p2 = malloc (sizeof (char) * (maxlen + 1));
  eics_get_cb ("Enter new password for keyfile: ", *p1, maxlen);
  eics_get_cb ("Verify new password for keyfile: ", *p2, maxlen);
  return 0;
}

/* The actual callback function */
int
eics_pass_cb (char *pass, int maxlen, int rwflag __attribute__((unused)), void *u)
{
  char *p1, *p2;
  memset (pass, 0, maxlen);
  /* This is used to determine if we are in STORE or READ mode */
  if (u)
    {
      /* Storing mode */
      get_compare_cb (&p1, &p2, maxlen);
      while ((strcmp (p1, p2)) || (strlen (p1) < MINPASSLEN))
	{
	  /* Not matching */
	  if (strcmp (p1, p2))
	    {
	      printf ("PASSWD: Did not match\n");
	    }
	  else
	    {
	      /* Too short */
	      printf ("PASSWD: Too short, minimum is %d letters\n",
		      MINPASSLEN);
	    }
	  /* Get new, better ones */
	  free (p1);
	  free (p2);
	  get_compare_cb (&p1, &p2, maxlen);
	}
      /* To avoid any overflows */
      memcpy (pass, p1,
	      ((maxlen - 1 >
		(int)strlen (p1) ? (int)strlen (p1) : maxlen - 1) + 1) * sizeof (char));
      *(pass + maxlen - 1) = '\0';
      memset (p1, 0, sizeof (char) * maxlen);
      memset (p2, 0, sizeof (char) * maxlen);
      /* Return password, erase copies */
      free (p1);
      free (p2);
    }
  else
    {
      p1 = malloc (sizeof (char) * (maxlen + 1));
      memset (p1, 0, sizeof (char) * (maxlen + 1));
      while (strlen (p1) < 1)
	{
	  eics_get_cb ("Enter your current password: ", p1, maxlen);
	}
      /* Again, to avoid buffer overflow */
      memcpy (pass, p1,
	      ((maxlen - 1 >
		(int)strlen (p1) ? (int)strlen (p1) : maxlen - 1) + 1) * sizeof (char));
      *(pass + maxlen - 1) = '\0';
      memset (p1, 0, sizeof (char) * maxlen);
      free (p1);
    }
  // final pass, trim for crlf
  if ((p1 = strchr(pass, '\n'))) *p1 ='\0';
  if ((p1 = strchr(pass, '\r'))) *p1 ='\0';
  return strlen (pass);
}
