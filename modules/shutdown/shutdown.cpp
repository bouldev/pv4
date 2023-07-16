#include <stdio.h>
#include <signal.h>

class Modules{
public:
	static void scheduleTeardown();
};

static void mdl_stdn_sigint_handler() {
	Modules::scheduleTeardown();
	printf("Allow a few seconds until exit\n");
	signal(SIGINT, SIG_DFL);
}

extern "C" void mdl_stdn_register_sigint_handler() {
	signal(SIGINT, (sighandler_t)mdl_stdn_sigint_handler);
}
