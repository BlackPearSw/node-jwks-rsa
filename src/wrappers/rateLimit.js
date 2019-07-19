import debug from 'debug';
import { RateLimiter } from 'limiter';

import JwksRateLimitError from '../errors/JwksRateLimitError';

export default function(client, { jwksRequestsPerMinute = 10 , jwksRequestsPerInterval, interval} = options) {
  const logger = debug('jwks');
  const getSigningKey = client.getSigningKey;

  let limiter;
  if (jwksRequestsPerInterval && interval) {
    limiter = new RateLimiter(jwksRequestsPerInterval, interval, true);
    logger(`Configured rate limiting to JWKS endpoint at ${jwksRequestsPerInterval}/${interval}`);
  } else {
    limiter = new RateLimiter(jwksRequestsPerMinute, 'minute', true);
    logger(`Configured rate limiting to JWKS endpoint at ${jwksRequestsPerMinute}/minute`);
  }

  return (kid, options, cb) => {
    if (!cb && typeof options === 'function') {
      cb = options;
    }

    limiter.removeTokens(1, (err, remaining) => {
      if (err) {
        return cb(err);
      }

      logger('Requests to the JWKS endpoint available for the next minute:', remaining);
      if (remaining < 0) {
        logger('Too many requests to the JWKS endpoint');
        return cb(new JwksRateLimitError('Too many requests to the JWKS endpoint'));
      } else {
        return getSigningKey(kid, options, cb);
      }
    });
  };
}
