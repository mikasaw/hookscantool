#include "engine.h"
#include "process_enum.h"
#include "ui_module_list.h"
#include "ui_process_tree.h"
#include "version.h"
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <d3d11.h>
#include <tchar.h>
#include <stdio.h>

/* Forward declare message handler from imgui_impl_win32.cpp */
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

/* Global DirectX resources */
static ID3D11Device*           g_pd3dDevice = NULL;
static ID3D11DeviceContext*    g_pd3dDeviceContext = NULL;
static IDXGISwapChain*         g_pSwapChain = NULL;
static ID3D11RenderTargetView* g_mainRenderTargetView = NULL;

/* Forward declarations */
static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

/* GUI panel forward declarations (from other ui_*.cpp files) */
extern void     ui_set_last_report(hook_report_t* r);
extern int      ui_hook_list_render(const hook_report_t* report);
extern void     ui_chain_view_render(const hook_entry_t* hook);
extern void     ui_restore_render(uint32_t pid, hook_report_t* report, int selected_hook);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
    /* Create application window */
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L,
                      hInstance, NULL, NULL, NULL, NULL, _T("HookScanTool"), NULL };
    RegisterClassEx(&wc);

    HWND hwnd = CreateWindow(wc.lpszClassName, _T("HookScanTool v" HOOKSCAN_VERSION_STR " - Windows Process Hook Scanner"),
                             WS_OVERLAPPEDWINDOW, 100, 100, 1280, 720,
                             NULL, NULL, wc.hInstance, NULL);

    /* Initialize Direct3D */
    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    /* Setup Dear ImGui context */
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    /* Setup Dear ImGui style */
    ImGui::StyleColorsDark();

    /* Setup Platform/Renderer backends */
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    /* State */
    int selected_hook = -1;
    bool show_about = false;

    /* Main loop */
    MSG msg;
    ZeroMemory(&msg, sizeof(msg));
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        /* --- Main layout (leave 22px for status bar) --- */
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y - 22));
        ImGui::Begin("Main", NULL,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
            ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_MenuBar);

        /* Menu bar */
        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu("File")) {
                if (ImGui::MenuItem("Exit", "Alt+F4")) {
                    PostQuitMessage(0);
                }
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Help")) {
                if (ImGui::MenuItem("About")) {
                    show_about = true;
                }
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }

        /* About dialog */
        if (show_about) {
            ImGui::OpenPopup("About HookScanTool");
            if (ImGui::BeginPopupModal("About HookScanTool", &show_about,
                ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::Text("HookScanTool v%s", HOOKSCAN_VERSION_STR);
                ImGui::Separator();
                ImGui::Text("Windows Process Hook Scanner");
                ImGui::Text("Detects IAT, EAT, and inline hooks in running processes.");
                ImGui::Separator();
                ImGui::Text("Engine: Zydis disassembler + PE parsing");
                ImGui::Text("GUI: Dear ImGui + DirectX 11");
                ImGui::Separator();
                if (ImGui::Button("Close")) {
                    show_about = false;
                }
                ImGui::EndPopup();
            }
        }

        /* Split layout: left panel (25%) | right area (75%) */
        float panel_width = io.DisplaySize.x * 0.25f;

        /* Left panel: Process tree */
        ImGui::BeginChild("LeftPanel", ImVec2(panel_width, 0), true);
        uint32_t selected_pid = ui_process_tree_render();
        ImGui::EndChild();

        ImGui::SameLine();

        /* Right area */
        ImGui::BeginChild("RightArea", ImVec2(0, 0), false);

        /* Top-right: Module triage panel (40%) */
        float module_height = io.DisplaySize.y * 0.40f;
        ImGui::BeginChild("ModulePanel", ImVec2(0, module_height), true);
        ui_module_list_render(selected_pid, ui_is_scanning());
        ImGui::EndChild();

        /* Middle-right: Hook list (30%) */
        float hook_height = io.DisplaySize.y * 0.30f;
        ImGui::BeginChild("HookList", ImVec2(0, hook_height), true);
        /* Merge reports: prefer selective scan report, fall back to full scan */
        hook_report_t* report = ui_module_get_last_report();
        if (!report) report = ui_get_last_report();
        selected_hook = ui_hook_list_render(report);
        ImGui::EndChild();

        /* Bottom-right: Chain view + Restore */
        ImGui::BeginChild("BottomRight", ImVec2(0, 0), true);

        /* Chain view takes most of the bottom */
        float chain_height = ImGui::GetContentRegionAvail().y - 80.0f;
        ImGui::BeginChild("ChainView", ImVec2(0, chain_height), true);
        if (report && selected_hook >= 0 && selected_hook < report->hook_count) {
            ui_chain_view_render(&report->hooks[selected_hook]);
        } else {
            ui_chain_view_render(NULL);
        }
        ImGui::EndChild();

        /* Restore panel */
        if (report && selected_pid != 0) {
            ui_restore_render(selected_pid, report, selected_hook);
        }

        ImGui::EndChild(); /* BottomRight */
        ImGui::EndChild(); /* RightArea */

        ImGui::End(); /* Main */

        /* --- Status bar --- */
        ImGui::SetNextWindowPos(ImVec2(0, io.DisplaySize.y - 22));
        ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, 22));
        ImGui::Begin("StatusBar", NULL,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings);

        {
            /* Left: PID and scan info */
            hook_report_t* status_report = ui_get_last_report();
            if (ui_is_scanning()) {
                ImGui::Text("Scanning...    ");
            } else if (status_report) {
                if (status_report->error_code != 0) {
                    ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f),
                        "PID %u: ERROR - %s", status_report->pid, status_report->error_msg);
                } else {
                    ImGui::Text("PID %u | Hooks: %d | Modules: %d | Time: %llu ms",
                        status_report->pid, status_report->hook_count,
                        status_report->modules_scanned,
                        (unsigned long long)status_report->scan_time_ms);
                }
            } else {
                ImGui::Text("Select a process and click Scan Selected");
            }

            /* Right: version */
            float status_w = ImGui::GetContentRegionAvail().x;
            ImGui::SameLine(status_w - 100);
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "v%s", HOOKSCAN_VERSION_STR);
        }

        ImGui::End();

        /* Rendering */
        ImGui::Render();
        const float clear_color[4] = { 0.1f, 0.1f, 0.1f, 1.00f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    /* Cleanup */
    ui_module_list_cleanup();
    ui_process_tree_cleanup();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}

static bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_0,
    };
    HRESULT res = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL,
        createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION,
        &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (FAILED(res))
        return false;

    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
}

static void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    if (FAILED(g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer))))
        return;
    if (FAILED(g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView))) {
        pBackBuffer->Release();
        return;
    }
    pBackBuffer->Release();
}

static void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam),
                DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}