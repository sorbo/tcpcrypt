#pragma warning(disable:4214)   // bit field types other than int

#pragma warning(disable:4201)   // nameless struct/union
#pragma warning(disable:4115)   // named type definition in parentheses
#pragma warning(disable:4127)   // conditional expression is constant
#pragma warning(disable:4054)   // cast of function pointer to PVOID
#pragma warning(disable:4244)   // conversion from 'int' to 'BOOLEAN', possible loss of data

typedef unsigned int u_int;

#define __BSD_VISIBLE 1

#include <ndis.h>
#include "passthru.h"
#include "ptextend.h"
#include "B2Winet.h"
#include "debug.h"
#include "ndisprot.h"
#include "nuiouser.h"
#include "macros.h"
#include "divert.h"
#include "filter.h"

