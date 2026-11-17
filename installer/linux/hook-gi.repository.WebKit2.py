from PyInstaller.utils.hooks.gi import GiModuleInfo, gir_library_path_fix

module_info = GiModuleInfo("WebKit2", "4.1")
if not module_info.available:
    module_info = GiModuleInfo("WebKit2", "4.0")

if module_info.available:
    typelib = gir_library_path_fix(module_info.typelib)
    datas = [typelib] if typelib else []
    hiddenimports = ["gi.repository.WebKit2"]
    hiddenimports += [
        f"gi.repository.{dependency.rsplit('-', 1)[0]}"
        for dependency in module_info.dependencies
    ]
