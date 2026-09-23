// Imprint MongoDB init - creates the app user (first start only)
const dbName = process.env.MONGO_DB || 'imprint';
db.getSiblingDB(dbName).createUser({
  user: process.env.MONGO_USER,
  pwd: process.env.MONGO_PASSWORD,
  roles: [{ role: 'readWrite', db: dbName }]
});
print(`Imprint user '${process.env.MONGO_USER}' created on '${dbName}'`);
