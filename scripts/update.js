const { readFile, readdir } = require('fs/promises');
const fetch = require('node-fetch');

// This mirrors the enum declared here https://github.com/ChatSift/AutoModerator/blob/main/libs/core/src/models.ts#L139-L147
const CATEGORIES = {
  malicious: 0,
  phishing: 1,
  scam: 2,
  spam: 3,
  shock: 4,
  // Currently unused apparently
  deceptive: 5,
  shortner: 6
};

const IGNORED = ['anime', 'gambling'];

const urlsFromFile = (content, category) => content
  .split('\n')
  .filter(line => line.length)
  .map(line => ({ url: line, category: CATEGORIES[category] }));

void (async () => {
  const urls = [];

  for (const dir of await readdir('./Domains')) {
    const category = dir.toLowerCase();

    if (IGNORED.includes(category)) {
      continue;
    }

    const files = await readdir(`./Domains/${dir}`);
    if (files.length === 1) {
      const contents = await readFile(`./Domains/${dir}/${files[0]}`, 'utf8');
      urls.push(...urlsFromFile(contents, category));
      continue;
    }

    for (const file of files) {
      const contents = await readFile(`./Domains/${dir}/${file}`, 'utf8');
      urls.push(...urlsFromFile(contents, 'shock'));
    }
  }

  const res = await fetch('https://api.automoderator.app/api/v1/filters/urls/bulk', {
    method: 'POST',
    body: JSON.stringify(urls),
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `App ${process.env.API_TOKEN}`
    }
  });

  const parsed = await res.json();

  if (!res.ok) {
    console.error('Non-ok status code', res.status, parsed);
    process.exit(1);
  }
})();
