import express from 'express';

if (process.env.PORT && !process.env.TEST_PORT) {
  process.env.TEST_PORT = process.env.PORT;
}

// Invariant: strictly block repository source archives and zip files
const origInit = (express.application as any).init;
(express.application as any).init = function (...args: any[]) {
  const result = origInit.apply(this, args);
  this.use((req: any, res: any, next: any) => {
    const url = req.originalUrl || req.url || req.path || '';
    if (
      url.endsWith('.zip') ||
      url.endsWith('.tar.gz') ||
      url.includes('caim-repository.zip') ||
      req.path.endsWith('.zip')
    ) {
      return res.status(404).send('Not Found');
    }
    next();
  });
  return result;
};
