import ms from 'ms';
import debug from 'debug';
import memoizer from 'lru-memoizer';

export default function(client, { cacheMaxEntries = 5, cacheMaxAge = ms('10h') } = options) {
  const logger = debug('jwks');
  const getSigningKey = client.getSigningKey;

  logger(`Configured caching of singing keys. Max: ${cacheMaxEntries} / Age: ${cacheMaxAge}`);
  return memoizer({
    load: (kid, options, callback) => {
      if (!callback && typeof options === 'function') {
        callback = options;
        options = undefined;
      }

      getSigningKey(kid, options, (err, key) => {
        if (err) {
          return callback(err);
        }

        logger(`Caching signing key for '${kid}':`, key);
        return callback(null, key);
      });
    },
    hash: (kid) => kid,
    maxAge: cacheMaxAge,
    max: cacheMaxEntries
  });
}
