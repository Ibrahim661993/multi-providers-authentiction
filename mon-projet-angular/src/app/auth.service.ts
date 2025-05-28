// src/app/auth.service.ts
import { Injectable } from '@angular/core';
import { OAuthService, AuthConfig } from 'angular-oauth2-oidc';
import { AuthInterceptor } from './auth.interceptor';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private currentTenant: any;
  private userProfile: any;

  constructor(private oauthService: OAuthService) { }

  private keycloakConfig: AuthConfig = {
    issuer: 'http://localhost:8080/realms/Alibou',
    redirectUri: 'http://localhost:4200',
    clientId: 'angular-client',
    scope: 'openid profile email',
    responseType: 'code',
    strictDiscoveryDocumentValidation: false,
  };

  private oktaConfig: AuthConfig = {
    issuer: 'https://dev-54238179.okta.com/oauth2/default',
    redirectUri: window.location.origin,
    clientId: '0oaotkzpk1nWBzWJj5d7',
    scope: 'openid profile email',
    responseType: 'code',
    strictDiscoveryDocumentValidation: false,
  };

  loginWithKeycloak(): void {
    this.currentTenant = 'tenant-keycloak';
    this.oauthService.configure(this.keycloakConfig);
    this.oauthService.loadDiscoveryDocumentAndLogin();
  }

  loginWithOkta(): void {
    this.currentTenant = 'tenant-okta';
    this.oauthService.configure(this.oktaConfig);
    this.oauthService.loadDiscoveryDocumentAndLogin();
  }

  logout(): void {
    this.currentTenant = '';
    this.oauthService.logOut();
    sessionStorage.clear();
    localStorage.clear();
    this.userProfile = null;
  }

  // get identityClaims() {
  //   return this.oauthService.loadUserProfile();
  // }

  async loadUserProfile() {
    this.userProfile = await this.oauthService.loadUserProfile();
  }

  get userInfo(): any {
    return this.userProfile;
  }

  get isLoggedIn(): boolean {
    return this.oauthService.hasValidAccessToken();
  }

  get accessToken(): string {
    return this.oauthService.getAccessToken();
  }
  get tenant(): string {
    return this.currentTenant;
  }

}
