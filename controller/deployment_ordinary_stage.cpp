#include "deployment_ordinary_args.h"
#include <windows.h>
int GateBouncerGuiMain(int, char **);
// Segunda defensa: Qt recibe sólo opciones propias reconstruidas.
extern "C" __declspec(dllexport) int GateBouncerGuiStageMain(int argc, wchar_t **wide) {
    if (!gb::controller::ordinaryArguments(argc, wide)) return 27;
    char program[] = "GateBouncer.exe", minimized[] = "--start-minimized";
    char *argv[] = {program, argc == 2 ? minimized : nullptr, nullptr};
    return GateBouncerGuiMain(argc, argv);
}
