import { Injectable, InternalServerErrorException } from '@nestjs/common';
import type { ServerMetadata, UserInfoResponse } from 'openid-client' with { 'resolution-mode': 'import' };
import { OAuthTokenEndpointAuthMethod } from 'src/enum';
import { LoggingRepository } from 'src/repositories/logging.repository';

export type OAuthConfig = {
  clientId: string;
  clientSecret?: string;
  issuerUrl: string;
  authorizeUrl?: string;
  tokenUrl?: string;
  userInfoUrl?: string;
  mobileOverrideEnabled: boolean;
  mobileRedirectUri: string;
  profileSigningAlgorithm: string;
  scope: string;
  signingAlgorithm: string;
  tokenEndpointAuthMethod: OAuthTokenEndpointAuthMethod;
  timeout: number;
};
export type OAuthProfile = UserInfoResponse;

@Injectable()
export class OAuthRepository {
  constructor(private logger: LoggingRepository) {
    this.logger.setContext(OAuthRepository.name);
  }

  async authorize(config: OAuthConfig, redirectUrl: string, state?: string, codeChallenge?: string) {
    const { buildAuthorizationUrl, randomState, randomPKCECodeVerifier, calculatePKCECodeChallenge } =
      await import('openid-client');
    const client = await this.getClient(config);
    state ??= randomState();

    let codeVerifier: string | null;
    if (codeChallenge) {
      codeVerifier = null;
    } else {
      codeVerifier = randomPKCECodeVerifier();
      codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
    }

    const params: Record<string, string> = {
      redirect_uri: redirectUrl,
      scope: config.scope,
      state,
    };

    if (client.serverMetadata().supportsPKCE()) {
      params.code_challenge = codeChallenge;
      params.code_challenge_method = 'S256';
    }

    const url = buildAuthorizationUrl(client, params).toString();

    return { url, state, codeVerifier };
  }

  async getLogoutEndpoint(config: OAuthConfig) {
    const client = await this.getClient(config);
    return client.serverMetadata().end_session_endpoint;
  }

  async getProfile(
    config: OAuthConfig,
    url: string,
    expectedState: string,
    codeVerifier: string,
  ): Promise<OAuthProfile> {
    const { allowInsecureRequests, authorizationCodeGrant, fetchUserInfo, ...oidc } = await import('openid-client');
    const client = await this.getClient(config);
    const pkceCodeVerifier = client.serverMetadata().supportsPKCE() ? codeVerifier : undefined;

    try {
      const tokens = await authorizationCodeGrant(client, new URL(url), {
        expectedState,
        pkceCodeVerifier,
        [allowInsecureRequests]: true,
      });
      const profile = await fetchUserInfo(client, tokens.access_token, oidc.skipSubjectCheck, {
        [allowInsecureRequests]: true,
      });
      if (!profile.sub) {
        throw new Error('Unexpected profile response, no `sub`');
      }

      return profile;
    } catch (error: Error | any) {
      if (error.message.includes('unexpected JWT alg received')) {
        this.logger.warn(
          [
            'Algorithm mismatch. Make sure the signing algorithm is set correctly in the OAuth settings.',
            'Or, that you have specified a signing key in your OAuth provider.',
          ].join(' '),
        );
      }

      this.logger.error(`OAuth login failed: ${error.message}`);
      this.logger.error(error);

      throw new Error('OAuth login failed', { cause: error });
    }
  }

  async getProfilePicture(url: string) {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to fetch picture: ${response.statusText}`);
    }

    return {
      data: await response.arrayBuffer(),
      contentType: response.headers.get('content-type'),
    };
  }

  private async getClient({
    issuerUrl,
    authorizeUrl,
    tokenUrl,
    userInfoUrl,
    clientId,
    clientSecret,
    profileSigningAlgorithm,
    signingAlgorithm,
    tokenEndpointAuthMethod,
    timeout,
  }: OAuthConfig) {
    try {
      const { Configuration } = await import('openid-client');

      // Manually fetch the discovery document to avoid issuer URL validation
      // This allows using an internal URL for discovery while overriding endpoints for split-horizon DNS
      const discoveryUrl = new URL('.well-known/openid-configuration', issuerUrl);
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      let metadata: Record<string, unknown>;
      try {
        const response = await fetch(discoveryUrl, { signal: controller.signal });
        if (!response.ok) {
          throw new Error(`Discovery request failed: ${response.status} ${response.statusText}`);
        }
        metadata = await response.json();
      } finally {
        clearTimeout(timeoutId);
      }

      // Override endpoints for split-horizon DNS setups
      // authorizeUrl: external URL for browser redirects
      // tokenUrl: can be internal for server-to-server communication
      // userInfoUrl: can be internal for server-to-server communication
      if (authorizeUrl) {
        metadata.authorization_endpoint = authorizeUrl;
        this.logger.debug(`Using custom authorization endpoint: ${authorizeUrl}`);
      }
      if (tokenUrl) {
        metadata.token_endpoint = tokenUrl;
        this.logger.debug(`Using custom token endpoint: ${tokenUrl}`);
      }
      if (userInfoUrl) {
        metadata.userinfo_endpoint = userInfoUrl;
        this.logger.debug(`Using custom userinfo endpoint: ${userInfoUrl}`);
      }

      // Create client configuration with the fetched metadata
      // Cast to ServerMetadata since we know the discovery response has the required fields
      const client = new Configuration(
        metadata as ServerMetadata,
        clientId,
        {
          client_secret: clientSecret,
          response_types: ['code'],
          userinfo_signed_response_alg: profileSigningAlgorithm === 'none' ? undefined : profileSigningAlgorithm,
          id_token_signed_response_alg: signingAlgorithm,
        },
        await this.getTokenAuthMethod(tokenEndpointAuthMethod, clientSecret),
      );

      return client;
    } catch (error: any | AggregateError) {
      this.logger.error(`Error in OAuth discovery: ${error}`, error?.stack, error?.errors);
      throw new InternalServerErrorException(`Error in OAuth discovery: ${error}`, { cause: error });
    }
  }

  private async getTokenAuthMethod(tokenEndpointAuthMethod: OAuthTokenEndpointAuthMethod, clientSecret?: string) {
    const { None, ClientSecretPost, ClientSecretBasic } = await import('openid-client');

    if (!clientSecret) {
      return None();
    }

    switch (tokenEndpointAuthMethod) {
      case OAuthTokenEndpointAuthMethod.ClientSecretPost: {
        return ClientSecretPost(clientSecret);
      }

      case OAuthTokenEndpointAuthMethod.ClientSecretBasic: {
        return ClientSecretBasic(clientSecret);
      }

      default: {
        return None();
      }
    }
  }
}
