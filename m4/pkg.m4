dnl PKG_WITH_MODULES(VARIABLE-PREFIX, MODULES,
dnl   [ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND],
dnl   [DESCRIPTION], [DEFAULT])
dnl ------------------------------------------
dnl
dnl Prepare a "--with-" configure option using the lowercase
dnl [VARIABLE-PREFIX] name, merging the behaviour of AC_ARG_WITH and
dnl PKG_CHECK_MODULES in a single macro.
AC_DEFUN([PKG_WITH_MODULES],
[
m4_pushdef([with_arg], m4_tolower([$1]))

m4_pushdef([description],
           [m4_default([$5], [build with ]with_arg[ support])])

m4_pushdef([def_arg], [m4_default([$6], [auto])])
m4_pushdef([def_action_if_found], [AS_TR_SH([with_]with_arg)=yes])
m4_pushdef([def_action_if_not_found], [AS_TR_SH([with_]with_arg)=no])

m4_case(def_arg,
            [yes],[m4_pushdef([with_without], [--without-]with_arg)],
            [m4_pushdef([with_without],[--with-]with_arg)])

AC_ARG_WITH(with_arg,
     AS_HELP_STRING(with_without, description[ @<:@default=]def_arg[@:>@]),,
    [AS_TR_SH([with_]with_arg)=def_arg])

AS_CASE([$AS_TR_SH([with_]with_arg)],
            [yes],[PKG_CHECK_MODULES([$1],[$2],$3,$4)],
            [auto],[PKG_CHECK_MODULES([$1],[$2],
                                        [m4_n([def_action_if_found]) $3],
                                        [m4_n([def_action_if_not_found]) $4])])

m4_popdef([with_arg])
m4_popdef([description])
m4_popdef([def_arg])

])dnl PKG_WITH_MODULES
