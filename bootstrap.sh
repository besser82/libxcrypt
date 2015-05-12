#!/bin/sh

AUTORECONF="`which autoreconf`"
FILLER="`echo ${AUTORECONF} | tr [A-z/\:] =`"
echo
echo
echo "Using autoreconf in:   ${AUTORECONF}"
echo "=======================${FILLER}"
echo

${AUTORECONF}		\
	--force		\
	--install	\
	--verbose	\
	-Wall
