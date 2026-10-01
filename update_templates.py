import re

def replace_in_file(filepath, pattern, replacement):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    content = re.sub(pattern, replacement, content, flags=re.DOTALL | re.IGNORECASE)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

# 1. Base HTML - Remove Anita's name from footer
replace_in_file('templates/base.html', r'&copy; 2026 ConfigScore.*?<\/p>', '&copy; 2026 ConfigScore. All rights reserved.</p>')
replace_in_file('templates/base.html', r'© 2026 ConfigScore.*?<\/p>', '&copy; 2026 ConfigScore. All rights reserved.</p>')

# 2. About HTML - Remove subtitle with Anita's name
replace_in_file('templates/about.html', r'<p class="subtitle">Designed &amp; Developed by Anita.*?<\/p>', '')
replace_in_file('templates/about.html', r'<p class="subtitle">Designed & Developed by Anita.*?<\/p>', '')
replace_in_file('templates/about.html', r'<p class="subtitle">.*?Anita.*?<\/p>', '')

print("HTML cleanup done.")
