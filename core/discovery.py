import os
import importlib.util
from glob import glob
from .module_base import KurokamiModule

def discover_modules(modules_dir: str = 'modules'):
    """
    Auto-discovers and registers modules matching 'k_*.py' in the given directory.
    Returns a dictionary mapping module names to instantiated module objects.
    """
    discovered_modules = {}
    
    if not os.path.exists(modules_dir):
        return discovered_modules
        
    search_pattern = os.path.join(modules_dir, 'k_*.py')
    module_files = glob(search_pattern)
    
    for file_path in module_files:
        module_name = os.path.basename(file_path)[:-3]  # strip .py
        
        # Load the module dynamically
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            
            # Find the class that subclasses KurokamiModule
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if isinstance(attr, type) and issubclass(attr, KurokamiModule) and attr is not KurokamiModule:
                    # Instantiate and register
                    instance = attr()
                    discovered_modules[instance.name] = instance
                    
    return discovered_modules
