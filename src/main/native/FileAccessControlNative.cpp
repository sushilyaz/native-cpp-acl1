#include <jni.h>
#include "org_example_FileAccessControl.h"
#include <windows.h>
#include <aclapi.h>
#include <vector>
#include <string>
#include <iostream>

bool BlockAccess();
bool AllowAccess();
bool UnblockSpecific(LPCWSTR path);
bool SetPermissions(LPCWSTR path, int act);
PSID GetLocalAdminSID();
bool ModifyPermissions(LPCWSTR path, PSID pAdminSID);
bool RemoveBlock(LPCWSTR path, PSID pAdminSID);
std::vector<std::wstring> GetFilesAndDirectories(LPCWSTR path);

void OutputDebugMessage(const wchar_t* message) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, message, -1, NULL, 0, NULL, NULL);
    std::string converted_message(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, message, -1, &converted_message[0], size_needed, NULL, NULL);

    std::cout << "Debug Message: " << converted_message << std::endl;
}

bool BlockAccess() {
    std::vector<std::wstring> filesAndDirs = GetFilesAndDirectories(L"C:\\UserFolder");
    for (const auto& path : filesAndDirs) {
        if (!SetPermissions(path.c_str(), 1)) {
            OutputDebugMessage(L"Failed to set permissions.");
            return false;
        }
    }
    return true;
}

bool AllowAccess() {
    std::vector<std::wstring> filesAndDirs = GetFilesAndDirectories(L"C:\\UserFolder");
    for (const auto& path : filesAndDirs) {
        if (!SetPermissions(path.c_str(), 2)) {
            OutputDebugMessage(L"Failed to set permissions.");
            return false;
        }
    }
    return true;
}

bool UnblockSpecific(LPCWSTR path) {
    if (!path) {
        OutputDebugMessage(L"Invalid path received.");
        return false;
    }
    return SetPermissions(path, 2);
}

bool SetPermissions(LPCWSTR path, int act) {
    PSID pAdminSID = GetLocalAdminSID();
    if (pAdminSID == NULL) {
        OutputDebugMessage(L"Failed to get local admin SID.");
        return false;
    }
    bool result = false;
    if (act == 1) {
        result = ModifyPermissions(path, pAdminSID);
    } else if (act == 2) {
        result = RemoveBlock(path, pAdminSID);
    }

    FreeSid(pAdminSID);
    return result;
}

bool ModifyPermissions(LPCWSTR path, PSID pAdminSID) {
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    EXPLICIT_ACCESSW ea[2];
    bool result = false;
    OutputDebugMessage(path);
    DWORD dwRes = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD);
    if (dwRes != ERROR_SUCCESS) {
        OutputDebugMessage(L"Failed to get named security info.");
        return false;
    }

    dwRes = SetEntriesInAclW(0, NULL, pOldDACL, &pNewDACL);
    if (dwRes != ERROR_SUCCESS) {
        LocalFree(pSD);
        OutputDebugMessage(L"Failed to set entries in ACL.");
        return false;
    }

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESSW) * 2);

    ea[0].grfAccessPermissions = GENERIC_READ;
    ea[0].grfAccessMode = DENY_ACCESS;
    ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[0].Trustee.ptstrName = (LPWSTR)pAdminSID;

  ea[1].grfAccessPermissions = GENERIC_WRITE;
  ea[1].grfAccessMode = DENY_ACCESS;
  ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  ea[1].Trustee.ptstrName = (LPWSTR)pAdminSID;

  for (int i = 0; i < 2; ++i) {
      dwRes = SetEntriesInAclW(1, &ea[i], pNewDACL, &pNewDACL);
      if (dwRes != ERROR_SUCCESS) {
          LocalFree(pSD);
          LocalFree(pNewDACL);
          OutputDebugMessage(L"Failed to set entries in ACL.");
          return false;
      }
  }

  dwRes = SetNamedSecurityInfoW(const_cast<LPWSTR>(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
  if (dwRes == ERROR_SUCCESS) {
      result = true;
  }

  if (pSD) {
      LocalFree(pSD);
  }
  if (pNewDACL) {
      LocalFree(pNewDACL);
  }

  return result;
}

bool RemoveBlock(LPCWSTR path, PSID pAdminSID) {
  PSECURITY_DESCRIPTOR pSD = NULL;
  PACL pOldDACL = NULL, pNewDACL = NULL;
  EXPLICIT_ACCESSW ea[2];
  bool result = false;

  DWORD dwRes = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD);
  if (dwRes != ERROR_SUCCESS) {
      OutputDebugMessage(L"Failed to get named security info.");
      return false;
  }

  ZeroMemory(&ea, sizeof(EXPLICIT_ACCESSW) * 2);

  for (int i = 0; i < 2; ++i) {
      ea[i].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
      ea[i].grfAccessMode = GRANT_ACCESS;
      ea[i].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
      ea[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
      ea[i].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
      ea[i].Trustee.ptstrName = (LPWSTR)pAdminSID;

      dwRes = SetEntriesInAclW(1, &ea[i], NULL, &pNewDACL);
      if (dwRes != ERROR_SUCCESS) {
          LocalFree(pSD);
          OutputDebugMessage(L"Failed to set entries in ACL.");
          return false;
      }
  }

  dwRes = SetNamedSecurityInfoW(const_cast<LPWSTR>(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
  if (dwRes == ERROR_SUCCESS) {
      result = true;
  }

  if (pSD) {
      LocalFree(pSD);
  }
  if (pNewDACL) {
      LocalFree(pNewDACL);
  }

  return result;
}

      PSID GetLocalAdminSID() {
          SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
          PSID pAdminSID = NULL;
          if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSID)) {
              OutputDebugMessage(L"Failed to allocate and initialize SID.");
              return NULL;
          }
          return pAdminSID;
      }

      std::vector<std::wstring> GetFilesAndDirectories(LPCWSTR path) {
          std::vector<std::wstring> result;
          WIN32_FIND_DATAW findFileData;
          std::wstring searchPath = std::wstring(path) + L"\\*";
          HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findFileData);

          if (hFind == INVALID_HANDLE_VALUE) {
              OutputDebugMessage(L"Invalid handle value for file search.");
              return result;
          }

          do {
              const std::wstring itemName = findFileData.cFileName;
              if (itemName != L"." && itemName != L"..") {
                  result.push_back(std::wstring(path) + L"\\" + itemName);
              }
          } while (FindNextFileW(hFind, &findFileData) != 0);

          FindClose(hFind);
          return result;
      }

      extern "C" {

      JNIEXPORT jboolean JNICALL Java_org_example_FileAccessControl_blockAccess(JNIEnv *env, jobject obj) {
          return BlockAccess() ? JNI_TRUE : JNI_FALSE;
      }

      JNIEXPORT jboolean JNICALL Java_org_example_FileAccessControl_allowAccess(JNIEnv *env, jobject obj) {
          return AllowAccess() ? JNI_TRUE : JNI_FALSE;
      }

      JNIEXPORT jboolean JNICALL Java_org_example_FileAccessControl_unblockSpecific(JNIEnv *env, jobject obj, jstring jPath) {
          const wchar_t* path = (const wchar_t*) env->GetStringChars(jPath, NULL);
          bool result = UnblockSpecific(path);
          env->ReleaseStringChars(jPath, (const jchar*)path);
          return result ? JNI_TRUE : JNI_FALSE;
      }

      }
