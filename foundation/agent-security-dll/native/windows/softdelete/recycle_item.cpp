#include <windows.h>
#include <shobjidl.h>
#include <wrl/client.h>
#include <wrl/implements.h>
#include "recovery.h"

using Microsoft::WRL::ComPtr;
using Microsoft::WRL::Make;
using Microsoft::WRL::RuntimeClass;
using Microsoft::WRL::RuntimeClassFlags;
using Microsoft::WRL::ClassicCom;

// Cancel if the shell proposes a permanent deletion. Only a recycle-bin
// item returned by PostDeleteItem confirms that recovery actually happened.
class RecycleReceipt final : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IFileOperationProgressSink> {
public:
    RecoveryStatus status = RECOVERY_UNTOUCHED;
    HRESULT STDMETHODCALLTYPE PreDeleteItem(DWORD flags, IShellItem*) override {
        if (!(flags & TSF_DELETE_RECYCLE_IF_POSSIBLE)) return E_ABORT;
        status = RECOVERY_UNKNOWN;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PostDeleteItem(DWORD, IShellItem*, HRESULT result, IShellItem* recycled) override {
        if (SUCCEEDED(result) && recycled) status = RECOVERY_RECYCLED;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE StartOperations() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE FinishOperations(HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PreRenameItem(DWORD, IShellItem*, LPCWSTR) override { return E_UNEXPECTED; }
    HRESULT STDMETHODCALLTYPE PostRenameItem(DWORD, IShellItem*, LPCWSTR, HRESULT, IShellItem*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PreMoveItem(DWORD, IShellItem*, IShellItem*, LPCWSTR) override { return E_UNEXPECTED; }
    HRESULT STDMETHODCALLTYPE PostMoveItem(DWORD, IShellItem*, IShellItem*, LPCWSTR, HRESULT, IShellItem*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PreCopyItem(DWORD, IShellItem*, IShellItem*, LPCWSTR) override { return E_UNEXPECTED; }
    HRESULT STDMETHODCALLTYPE PostCopyItem(DWORD, IShellItem*, IShellItem*, LPCWSTR, HRESULT, IShellItem*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PreNewItem(DWORD, IShellItem*, LPCWSTR) override { return E_UNEXPECTED; }
    HRESULT STDMETHODCALLTYPE PostNewItem(DWORD, IShellItem*, LPCWSTR, LPCWSTR, DWORD, HRESULT, IShellItem*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE UpdateProgress(UINT, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ResetTimer() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PauseTimer() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ResumeTimer() override { return S_OK; }
};

extern "C" RecoveryStatus recycle_item(const wchar_t *path) {
    HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(init) && init != RPC_E_CHANGED_MODE) return RECOVERY_UNTOUCHED;
    RecoveryStatus status = RECOVERY_UNTOUCHED;
    {
        ComPtr<IShellItem> item;
        ComPtr<IFileOperation> operation;
        auto receipt = Make<RecycleReceipt>();
        if (receipt && SUCCEEDED(SHCreateItemFromParsingName(path, nullptr, IID_PPV_ARGS(&item)))
            && SUCCEEDED(CoCreateInstance(CLSID_FileOperation, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&operation)))
            && SUCCEEDED(operation->SetOperationFlags(FOFX_RECYCLEONDELETE | FOF_NO_UI | FOFX_EARLYFAILURE))
            && SUCCEEDED(operation->DeleteItem(item.Get(), receipt.Get()))) {
            operation->PerformOperations();
            status = receipt->status;
        }
    }
    if (SUCCEEDED(init)) CoUninitialize();
    return status;
}
