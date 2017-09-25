; // https://artfulcode.wordpress.com/
; // https://github.com/cmovz/
; // License: use it as you wish, just keep this notice. No liability taken.

#include <windows.h>

static inline BOOL _is_iid_end(IMAGE_IMPORT_DESCRIPTOR* iid)
{
  return !iid->Characteristics && !iid->TimeDateStamp && !iid->ForwarderChain
          && !iid->Name && !iid->FirstThunk;
}

static BOOL _load_from_hints(IMAGE_IMPORT_DESCRIPTOR* iid, DWORD base)
{
  HMODULE dll = LoadLibrary((LPCSTR)(base + iid->Name));
  if(!dll){
    return FALSE;
  }
  
  // now get the address of each of the functions in the thunks
  DWORD* hints = (DWORD*)(base + iid->Characteristics);
  DWORD* thunks = (DWORD*)(base + iid->FirstThunk);
  while(*hints){
    DWORD r;
  
    if(*hints & 0x80000000){
      // handle import by ordinal
      r = (DWORD)GetProcAddress(dll, (LPCSTR)(*hints & 0xffff));
    }
    else {
      // handle import by name
      IMAGE_IMPORT_BY_NAME* iibn = (IMAGE_IMPORT_BY_NAME*)(base + *hints);
      r = (DWORD)GetProcAddress(dll, iibn->Name);
    }
    
    if(!r){
      return FALSE;
    }
    
    *thunks = r;
    ++thunks;
    ++hints;
  }
  
  return TRUE;
}

/*
  fill_idata() fills the function references in the .idata section. There's no
  cleaning up if it fails because it assumes the program won't be able to run
  anyway and will have to exit. References to modules are also lost because
  the DLLs should be in the address space until the program exits. In short,
  it behaves just like the Windows PE loader.
*/
BOOL fill_idata(DWORD* idata, DWORD base)
{
  IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)idata;

  while(!_is_iid_end(iid)){
    if(!_load_from_hints(iid, base)){
      return FALSE;
    } 
    
    ++iid;
  }
  
  return TRUE;
}
