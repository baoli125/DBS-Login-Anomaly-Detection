import os
import re

emoji_pattern = re.compile('[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF\U0001F900-\U0001FAFF\uFE0F]')
count = 0
files_processed = 0
for root, dirs, files in os.walk('.'):
    for f in files:
        if f.endswith(('.py', '.md', '.json', '.txt')):
            path = os.path.join(root, f)
            files_processed += 1
            with open(path, 'r', encoding='utf-8', errors='ignore') as fp:
                text = fp.read()
            newtext = emoji_pattern.sub('', text)
            if newtext != text:
                with open(path, 'w', encoding='utf-8') as fp:
                    fp.write(newtext)
                count += 1

print(f'Files scanned: {files_processed}')
print(f'Files modified: {count}')
