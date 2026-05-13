const queue = require('./queue'); queue.process('import', async (job) => { const metadata = job.data; return metadata; });
