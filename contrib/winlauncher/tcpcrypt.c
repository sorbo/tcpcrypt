#include <windows.h>
#include <stdio.h>
#include <devguid.h>
#include <winsock2.h>
#include <unistd.h>

#define COBJMACROS

#include "netcfgx.h"
#include "netcfgapi.h"
#include "resource.h"

#define WM_TERM (WM_APP + 1)

static HANDLE _tcpcryptd = INVALID_HANDLE_VALUE;
static HWND _hwnd;
static HINSTANCE _hinstance;
static NOTIFYICONDATA _nid[2];
static NOTIFYICONDATA *_nidcur = NULL;

static WINAPI DWORD check_term(void *arg)
{
	WaitForSingleObject(_tcpcryptd, INFINITE);

	_tcpcryptd = INVALID_HANDLE_VALUE;

	if (!PostMessage(_hwnd, WM_TERM, 0, 0))
		MessageBox(_hwnd, "PostMessage()", "Error", MB_OK);

	return 0;
}

static void stop()
{
	if (_tcpcryptd != INVALID_HANDLE_VALUE) {
		if (!TerminateProcess(_tcpcryptd, 0))
			MessageBox(_hwnd, "TerminateProcess()", "Error", MB_OK);
	}

	_tcpcryptd = INVALID_HANDLE_VALUE;
}

static void die(int rc)
{
	stop();

	if (_nidcur)
		Shell_NotifyIcon(NIM_DELETE, _nidcur);

	exit(rc);
}

static void err(int rc, char *fmt, ...)
{
	va_list ap;
	char buf[4096];
	DWORD e;

	buf[0] = 0;
	e = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
		      NULL,
		      e,
		      0,
		      buf,
		      sizeof(buf),
		      NULL);

	printf("ERR %ld [%s]\n", e, buf);

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	MessageBox(_hwnd, buf, "Error", MB_OK);

	die(rc);
}

static void start()
{
	char cmd[1024];
	char arg[1024];
	PROCESS_INFORMATION pi;
	STARTUPINFO si;

	snprintf(cmd, sizeof(cmd), "tcpcryptd.exe");
	snprintf(arg, sizeof(arg), "%s", cmd);

	memset(&si, 0, sizeof(si));
	si.cb		 = sizeof(si);
	si.wShowWindow   = SW_HIDE;
        si.dwFlags      |= STARTF_USESHOWWINDOW;

	if (!CreateProcess(cmd,
		      arg,
		      NULL,
		      NULL,
		      FALSE,
		      0,
		      NULL,
		      NULL,
		      &si,
		      &pi))
		err(1, "CreateProcess()");

	_tcpcryptd = pi.hProcess;

	if (!CreateThread(NULL, 0, check_term, NULL, 0, NULL))
		err(1, "CreateThread()");
}

static void netstat()
{
	char cmd[1024];
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	HANDLE out[2], e[2];
	SECURITY_ATTRIBUTES sa;
	HWND edit;
	DWORD rd;
	int l;

	edit = GetDlgItem(_hwnd, IDC_EDIT1);

	snprintf(cmd, sizeof(cmd), "tcnetstat.exe");

        memset(&sa, 0, sizeof(sa));
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        if (!CreatePipe(&out[0], &out[1], &sa, 0))                                  
                err(1, "CreatePipe()");

        if (!SetHandleInformation(out[0], HANDLE_FLAG_INHERIT, 0))
                err(1, "SetHandleInformation()");

        if (!DuplicateHandle(GetCurrentProcess(), out[1],
                             GetCurrentProcess(), &e[1], 0,
                             TRUE,DUPLICATE_SAME_ACCESS))
                err(1, "DuplicateHandle()");
	
        memset(&si, 0, sizeof(si));
        si.cb            = sizeof(si);
        si.dwFlags      |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdInput     = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput    = out[1];
        si.hStdError     = e[1];
	si.wShowWindow   = SW_HIDE;

	if (!CreateProcess(cmd,
		      NULL,
		      NULL,
		      NULL,
		      TRUE,
		      0,
		      NULL,
		      NULL,
		      &si,
		      &pi))
		err(1, "CreateProcess()");

        CloseHandle(out[1]);
        CloseHandle(e[1]);

	SetWindowText(edit, "");
	SetFocus(edit);
	l = 0;
	while (1) {
		int l;

		if (!ReadFile(out[0], cmd, sizeof(cmd) - 1, &rd, NULL))
			break;

		cmd[rd] = 0;

		SendMessage(edit, EM_SETSEL, l, l);
		SendMessage(edit, EM_REPLACESEL, 0, (LPARAM) cmd);
		l += strlen(cmd);
	}

	CloseHandle(out[0]);
}

static void minimize(HWND hwnd)
{
	ShowWindow(hwnd, SW_HIDE);
}

static void do_stop(HWND dlg)
{
	HWND button = GetDlgItem(dlg, IDOK);

	SetWindowText(button, "Start");

	SetWindowText(GetDlgItem(dlg, IDC_EDIT2), "tcpcrypt off");

	_nidcur = &_nid[0];
	Shell_NotifyIcon(NIM_MODIFY, _nidcur);
	SendMessage(_hwnd, WM_SETICON, ICON_SMALL, (LPARAM) _nidcur->hIcon);
}

static void add_text(char *x)
{
}

static void start_stop(HWND dlg)
{
	HWND button = GetDlgItem(dlg, IDOK);

	if (!button)
		err(1, "GetDlgItem()");

	if (_tcpcryptd == INVALID_HANDLE_VALUE) {
		start();
		SetWindowText(button, "Stop");
		SetWindowText(GetDlgItem(dlg, IDC_EDIT2), "tcpcrypt ON!");
		_nidcur = &_nid[1];
		Shell_NotifyIcon(NIM_MODIFY, _nidcur);
		SendMessage(_hwnd, WM_SETICON, ICON_SMALL,
			    (LPARAM) _nidcur->hIcon);
	} else {
		stop();
		do_stop(dlg);
	}
}

static void setup_icons(void)
{
	memset(&_nid[0], 0, sizeof(*_nid));

	_nid[0].cbSize			= sizeof(*_nid);
	_nid[0].hWnd			= _hwnd;
	_nid[0].uID			= 0;
	_nid[0].uFlags			= NIF_ICON | NIF_MESSAGE | NIF_TIP;
	_nid[0].uCallbackMessage	= WM_USER;
	_nid[0].hIcon			= LoadIcon(_hinstance,
					   MAKEINTRESOURCE(IDI_OFF));

	if (!_nid[0].hIcon)
		err(1, "LoadIcon()");

	strcpy(_nid[0].szTip, "tcpcrypt off");

	memcpy(&_nid[1], &_nid[0], sizeof(*_nid));

	_nid[1].hIcon = LoadIcon(_hinstance, MAKEINTRESOURCE(IDI_ON));
	if (!_nid[1].hIcon)
		err(1, "LoadIcon()");

	strcpy(_nid[1].szTip, "tcpcrypt ON");

	_nidcur = &_nid[0];

	Shell_NotifyIcon(NIM_ADD, _nidcur);
	SendMessage(_hwnd, WM_SETICON, ICON_SMALL, (LPARAM) _nidcur->hIcon);
}

static void parse_guid(unsigned char *guid, char *in)
{
	int x = 0;
	int len = strlen(in);

	while (len >= 2) {
		char tmp[3];
		int num;

		if (*in == '-') {
			len--;
			in++;
			continue;
		}

		tmp[0] = in[0];
		tmp[1] = in[1];
		tmp[2] = 0;
	
		if (sscanf(tmp, "%x", &num) != 1)
			err(1, "sscanf()");

		*guid++ = num;
		x++;

		if (x == 16)
			break;

		in  += 2;
		len -= 2;
	}

	if (x != 16)
		err(1, "parse_guid() [%d]", x);
}

static void install_divert(void)
{
	INetCfg    *pnc;
	LPTSTR     lpszApp;
	char dir[_MAX_PATH];
	char inf[2][_MAX_PATH];
	char *p;
	HRESULT hr;
	int i;

	if (!GetModuleFileName(NULL, dir, sizeof(inf)))
		err(1, "GetModuleFileName()");

	p = strrchr(dir, '\\');
	if (p)
		p[1] = 0;

	snprintf(inf[0], _MAX_PATH, "%s%s", dir, "netsf.inf");
	snprintf(inf[1], _MAX_PATH, "%s%s", dir, "netsf_m.inf");

	if (HrGetINetCfg(TRUE, "tcpcrypt", &pnc, &lpszApp ) != S_OK)
		err(1, "HrGetINetCfg()");

	for (i = 0; i < 2; i++) {
		if (!SetupCopyOEMInf(
		    inf[i],
		    dir, // Other files are in the
		    // same dir. as primary INF
		    SPOST_PATH,    // First param is path to INF
		    0,             // Default copy style
		    NULL,          // Name of the INF after
		    // it's copied to %windir%\inf
		    0,             // Max buf. size for the above               
		    NULL,          // Required size if non-null
		    NULL)          // Optionally get the filename
		    // part of Inf name after it is copied.
		    )
			err(1, "SetupCopyOEMInf()");
        }

	hr = HrInstallNetComponent(pnc,
				   L"ms_passthru",
				   &GUID_DEVCLASS_NETSERVICE,
				   NULL);

	if (hr != S_OK && hr != NETCFG_S_REBOOT)
		err(1, "HrInstallNetComponent()");

	HrReleaseINetCfg(pnc, TRUE);
}

static int probe_divert(void)
{
        HANDLE h;
        
        h = CreateFile(
                "\\\\.\\PassThru",
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                INVALID_HANDLE_VALUE);

	if (h == INVALID_HANDLE_VALUE)
		return 0;

	CloseHandle(h);

	return 1;
}

static void setup_divert(void)
{
	if (probe_divert())
		return;

	MessageBox(NULL, "About to install the tcpcrypt driver."
	 "  You might need to press OK a couple of times depending on how many NICs you got.",
		   "tcpcrypt", MB_OK);

	install_divert();

	if (!probe_divert())
		err(1, "install_divert()");
}

static void do_init(void)
{
	setup_icons();
	setup_divert();
}

LRESULT CALLBACK DlgProc(HWND hWndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
        switch (Msg) {
	case WM_USER:
		switch (lParam) {
		case WM_LBUTTONDBLCLK:
			ShowWindow(hWndDlg, SW_SHOW);
			return TRUE;
		}
		break;
		
	case WM_TERM:
		do_stop(hWndDlg);
		break;

	case WM_INITDIALOG:
		_hwnd = hWndDlg;
		do_init();
		do_stop(_hwnd);
		break;

	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_MINIMIZE) {
			minimize(hWndDlg);
			return TRUE;
		}
		break;

        case WM_CLOSE:
		minimize(hWndDlg);
                return TRUE;

        case WM_COMMAND:
                switch(wParam) {
		case IDOK:
			start_stop(hWndDlg);
			return TRUE;
		case IDCANCEL:
			netstat();
			return TRUE;

		case IDC_BUTTON1:
			EndDialog(hWndDlg, 0);
			return TRUE;
		}
		break;
	}

	return FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR szCmdLine, int iCmdShow)
{
	_hinstance = hInstance;

	if (DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL,
		  (DLGPROC) DlgProc) == -1)
		err(1, "DialogBox()");

	die(0);
}
