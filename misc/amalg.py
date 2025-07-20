#!/usr/bin/env python3
"""
AmalgamationBuilder - Implementation with improved #line support
"""

import re
import os
from typing import Set

class AmalgamationBuilder:
    def __init__(self):
        self.body = ""
        self.local_includes: Set[str] = set()  # These should deduplicate items
        self.global_includes: Set[str] = set()
    
    def add(self, filepath: str):
        """Add a file to the amalgamation"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Warning: File '{filepath}' not found, skipping")
            return
        
        original_line_number = 1
        skipped_lines = 0
        first_content_line = True
        
        for line in lines:
            # Check if the line is an include
            if self._is_include_line(line):
                include_info = self._extract_include_info(line)
                if include_info:
                    filename, uses_angular_brackets = include_info
                    if uses_angular_brackets:
                        self.global_includes.add(filename)
                    else:
                        self.local_includes.add(filename)
                
                original_line_number += 1
                skipped_lines += 1
                continue
            
            # Check if the line is part of a header guard
            if self._is_header_guard_line(line):
                original_line_number += 1
                skipped_lines += 1
                continue
            
            # Skip empty lines at the beginning of files
            if first_content_line and line.strip() == '':
                original_line_number += 1
                skipped_lines += 1
                continue
            
            # Add #line directive when starting a new file or after skipping significant content
            if first_content_line or skipped_lines > 0:
                # Only add #line if we skipped lines or it's a new file
                # self.body += f'#line {original_line_number} "{filepath}"\n'
                first_content_line = False
                skipped_lines = 0
            
            # Append the current line to body
            self.body += line
            original_line_number += 1
    
    def _is_include_line(self, line: str) -> bool:
        """Check if a line is an #include directive"""
        # Skip obviously non-include lines for performance
        if '#include' not in line:
            return False
        
        # Check if this line is commented out
        if self._is_line_commented(line):
            return False
        
        # Regex to match include pattern
        include_pattern = re.compile(r'^\s*#\s*include\s*[<"][^>"]+[>"]')
        return bool(include_pattern.match(line.strip()))
    
    def _extract_include_info(self, line: str) -> tuple[str, bool] | None:
        """Extract filename and bracket type from include line"""
        # Pattern to capture include details
        include_pattern = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)([>"])')
        match = include_pattern.match(line.strip())
        
        if match:
            open_delim = match.group(1)
            filename = match.group(2)
            close_delim = match.group(3)
            
            # Validate matching delimiters
            if (open_delim == '<' and close_delim == '>') or \
               (open_delim == '"' and close_delim == '"'):
                uses_angular_brackets = (open_delim == '<')
                return filename, uses_angular_brackets
        
        return None
    
    def _is_header_guard_line(self, line: str) -> bool:
        """Check if a line is part of a header guard (assumes _INCLUDED suffix)"""
        stripped = line.strip()
        
        # Simplified header guard patterns for _INCLUDED suffix
        header_guard_patterns = [
            re.compile(r'#ifndef\s+\w+_INCLUDED'),
            re.compile(r'#define\s+\w+_INCLUDED'),
            re.compile(r'#endif\s*//.*_INCLUDED'),
            re.compile(r'#endif\s*/\*.*_INCLUDED.*\*/'),
        ]
        
        return any(pattern.match(stripped) for pattern in header_guard_patterns)
    
    def _is_line_commented(self, line: str) -> bool:
        """Basic check if line is commented out"""
        include_pos = line.find('#include')
        if include_pos == -1:
            return False
        
        # Check for // comment before #include
        comment_pos = line.find('//')
        if comment_pos != -1 and comment_pos < include_pos:
            return True
        
        # Check for /* comment before #include (basic case)
        before_include = line[:include_pos]
        if '/*' in before_include and '*/' not in before_include:
            return True
        
        return False
    
    def result(self) -> str:
        """Generate the final amalgamated result"""
        result = ""
        
        # Write all global includes at the top
        for item in sorted(self.global_includes):
            result += f'#include <{item}>\n'
        
        if self.global_includes:
            result += "\n"  # Add spacing after includes
        
        # Add the body content
        result += self.body
        
        return result


def main():
    """Example usage of AmalgamationBuilder"""
    
    # Build the header
    print("Building header...")
    header_builder = AmalgamationBuilder()
    
    header_files = [
        "src/basic.h",
        "src/parse.h", 
        "src/engine.h",
        "src/client.h",
        "src/server.h",
        "src/cert.h",
        "src/router.h"
    ]
    
    for file in header_files:
        header_builder.add(file)
    
    header = header_builder.result()
    
    # Build the source
    print("Building source...")
    source_builder = AmalgamationBuilder()
    
    source_files = [
        "src/cert.h",
        "src/socket.h", 
        "src/basic.c",
        "src/parse.c",
        "src/engine.c",
        "src/socket.c",
        "src/client.c",
        "src/server.c",
        "src/router.c"
    ]
    
    for file in source_files:
        source_builder.add(file)
    
    source = source_builder.result()
    
    # Write results
    print("Writing http.h...")
    with open("http.h", 'w', encoding='utf-8') as f:
        f.write('/*\n')
        f.write(' * HTTP Library - Amalgamated Header\n')
        f.write(' * Generated automatically - do not edit manually\n')
        f.write(' */\n\n')
        f.write('#ifndef HTTP_AMALGAMATION_H\n')
        f.write('#define HTTP_AMALGAMATION_H\n\n')
        f.write('#ifdef __cplusplus\n')
        f.write('extern "C" {\n')
        f.write('#endif\n\n')
        f.write(header)
        f.write('\n#ifdef __cplusplus\n')
        f.write('}\n')
        f.write('#endif\n\n')
        f.write('#endif /* HTTP_AMALGAMATION_H */\n')
    
    print("Writing http.c...")
    with open("http.c", 'w', encoding='utf-8') as f:
        f.write('/*\n')
        f.write(' * HTTP Library - Amalgamated Source\n')
        f.write(' * Generated automatically - do not edit manually\n')
        f.write(' */\n\n')
        f.write('#include "http.h"\n\n')
        f.write(source)
    
    print("Amalgamation complete!")
    print(f"Header: {len(header.splitlines())} lines")
    print(f"Source: {len(source.splitlines())} lines")
    
    # Show some statistics
    print(f"\nHeader global includes: {len(header_builder.global_includes)}")
    print(f"Source global includes: {len(source_builder.global_includes)}")
    print(f"Local includes found: {len(header_builder.local_includes | source_builder.local_includes)}")


if __name__ == "__main__":
    main()