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

  // configureTenant(tenant?: string) {
  //   if (tenant === 'tenant-okta') {
  //     this.currentTenant = 'tenant-okta';
  //     this.oauthService.configure(this.oktaConfig);
  //   } else {
  //     // Par défaut keycloak
  //     this.currentTenant = 'tenant-keycloak';
  //     this.oauthService.configure(this.keycloakConfig);
  //   }
  // }
  configureTenant(tenant: string) {
    this.currentTenant = tenant;
    if (tenant == 'tenant-okta') {
      this.oauthService.configure(this.oktaConfig);
    } else {
      this.oauthService.configure(this.keycloakConfig);
    }
  }


  async initAuth() {
    const savedTenant = localStorage.getItem('currentTenant') || 'tenant-keycloak';
    this.configureTenant(savedTenant);
    const loggedIn = await this.oauthService.loadDiscoveryDocumentAndTryLogin();
    if (loggedIn) {
      await this.loadUserProfile();
    }
  }


  async loginWithKeycloak(): Promise<void> {
    this.currentTenant = 'tenant-keycloak';
    localStorage.setItem('currentTenant', this.currentTenant);

    this.oauthService.configure(this.keycloakConfig);
    // charge le document de découverte et déclenche login
    const loggedIn = await this.oauthService.loadDiscoveryDocumentAndLogin();
    if (loggedIn) {
      // si login OK, charge le profil utilisateur
      await this.loadUserProfile();
    }
  }
  async loginWithOkta(): Promise<void> {
    this.currentTenant = 'tenant-okta';
    localStorage.setItem('currentTenant', this.currentTenant);

    this.oauthService.configure(this.oktaConfig);
    // charge le document de découverte et déclenche login
    const loggedIn = await this.oauthService.loadDiscoveryDocumentAndLogin();
    if (loggedIn) {
      // si login OK, charge le profil utilisateur
      await this.loadUserProfile();
    }
  }



  logout(): void {
    this.currentTenant = '';
    this.oauthService.logOut();
    sessionStorage.clear();
    localStorage.clear();
    this.userProfile = null;
  }


  async loadUserProfile() {
    try {
      // Récupère le profile de base via /userinfo
      const profile = await this.oauthService.loadUserProfile();

      // Récupère le token
      const token = this.oauthService.getAccessToken();

      if (token) {
        const payload = JSON.parse(atob(token.split('.')[1])); // décode le token JWT
        // Fusionne les données du token (rôles etc.) avec le profile de base
        this.userProfile = {
          ...profile,
          ...payload,
        };
        console.log('Profil utilisateur enrichi :', this.userProfile);
      } else {
        this.userProfile = profile;
      }
    } catch (error) {
      console.error('Erreur lors du chargement du profil :', error);
    }
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