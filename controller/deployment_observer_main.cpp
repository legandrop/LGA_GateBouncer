int GateBouncerGuiMain(int, char **);
// Entrada exclusiva del target de observación aislada; no carga el stage productivo.
#ifdef QT_NEEDS_QMAIN
int qMain(int argc,char **argv) { return GateBouncerGuiMain(argc,argv); }
#else
int main(int argc,char **argv) { return GateBouncerGuiMain(argc,argv); }
#endif
