#!/usr/bin/env python3

import importlib.util
from pathlib import Path

class PackerDetector:
    # Initializes the detector with file path, binary type (ELF/PE) and calculated entropy
    # it immediately attempts to load plugins and run the detection logic
    def __init__(self, filepath, binary_type, entropy):
        self.filepath = filepath
        self.binary_type = binary_type
        self.entropy = entropy
        self.detected_packer = None
        self.confidence = 0
        
        # load external detection modules and run them
        self._load_packer_modules()
        self._detect()
    
    # dynamically loads python scripts from the 'packer/' directory
    # this allows adding new packer signatures without changing the main code
    def _load_packer_modules(self):
        self.packer_modules = []
        
        # locate the 'packer' directory relative to this script
        packer_dir = Path(__file__).parent.parent / "packer"
        
        if not packer_dir.exists():
            return
        
        # iterate over all .py files in that directory
        for packer_file in packer_dir.glob("*.py"):
            # skip __init__.py or other internal files
            if packer_file.name.startswith("__"):
                continue
            
            try:
                # dynamic import magic using importlib
                module_name = packer_file.stem
                spec = importlib.util.spec_from_file_location(module_name, packer_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # verify that the loaded module has a detect function
                # this ensures the plugin follows the required interface
                if hasattr(module, 'detect'):
                    self.packer_modules.append(module)
            except Exception as e:
                # silently ignore broken modules to prevent crashing the main app
                pass
    
    # runs the detect function of every loaded module
    # selects the result with the highest confidence score
    def _detect(self):
        if not self.packer_modules:
            return
        
        best_match = None
        best_confidence = 0
        
        # Check against all loaded packer definitions
        for module in self.packer_modules:
            try:
                # pass file info to the module
                result = module.detect(self.filepath, self.binary_type, self.entropy)
                
                # if module returns a valid result with a confidence score
                if result and 'confidence' in result:
                    # keep the one with the highest confidence
                    if result['confidence'] > best_confidence:
                        best_confidence = result['confidence']
                        best_match = result
            except Exception as e:
                pass
        
        # if we found a match with at least 50% confidence, record it
        if best_match and best_confidence >= 50:
            self.detected_packer = best_match.get('name', 'Unknown')
            self.confidence = best_confidence
    
    # prints the detection results to the console.
    def display(self):
        # warn if no plugins were loaded
        if not self.packer_modules:
            print(f"[!] The packer/ folder was either not found or is empty.")
            print(f"Status: Module missing")
            return
        
        # case 1 - a specific packer was identified by a plugin
        if self.detected_packer:
            print(f"Status: Packaged")
            print(f"Packer: {self.detected_packer}")
            print(f"Confidence: {self.confidence}%")
        else:
            # case 2 - no specific packer found, but Entropy is high (> 7.5)
            # high entropy usually indicates compression or encryption
            if self.entropy and self.entropy >= 7.5:
                print(f"Status: Probably packaged")
                print(f"Packer: Not detected (High entropy)")
            # case 3: - low entropy and no packer signature found
            else:
                print(f"Status: Unpackaged")
                print(f"Packer: Not found")
