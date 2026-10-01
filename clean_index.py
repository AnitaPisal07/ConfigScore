import re

with open('templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove the hero badge completely
content = re.sub(r'<span class="hero-badge">.*?</span>', '', content, flags=re.DOTALL)

# Remove the whole hero-preview div
content = re.sub(r'<!-- Sample Score Preview Card -->.*?</div>\s*</div>\s*</section>', '</div>\n</section>', content, flags=re.DOTALL)

with open('templates/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print('Cleaned index.html')
