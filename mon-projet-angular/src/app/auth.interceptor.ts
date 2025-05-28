// src/app/auth.interceptor.ts
import { Injectable } from '@angular/core';
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
} from '@angular/common/http';
import { Observable } from 'rxjs';
import { OAuthService } from 'angular-oauth2-oidc';
import { AuthService } from './auth.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private authService: AuthService) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const token=this.authService.accessToken;
    const tenant = this.authService.tenant;

    let headers = req.headers;
    if (token) {
      headers = headers.set('Authorization', `Bearer ${token}`);
    }
    
  const isUserInfoRequest = req.url.includes('/userinfo');
    if (tenant && token && !isUserInfoRequest) {
       headers = headers.set('X-Tenant-ID', tenant);
    }

    const clonedRequest = req.clone({ headers });
    return next.handle(clonedRequest);
}
}


// import { Injectable } from '@angular/core';
// import {
//   HttpInterceptor,
//   HttpRequest,
//   HttpHandler,
//   HttpEvent
// } from '@angular/common/http';
// import { Observable } from 'rxjs';
// import { OAuthService } from 'angular-oauth2-oidc';

// @Injectable()
// export class AuthInterceptor implements HttpInterceptor {

//   // Stocke ici le tenant courant (à mettre à jour au login)
//   private selectedTenant: string | null = null;

//   constructor(private oauthService: OAuthService) {}

//   // Appelle cette méthode au login Angular pour changer de tenant
//   public setTenant(tenantId: string) {
//     this.selectedTenant = tenantId;
//   }

//   intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
//     let headers = req.headers;

//     const token = this.oauthService.getAccessToken();
//     if (token) {
//       headers = headers.set('Authorization', 'Bearer ' + token);
//     }

//     if (this.selectedTenant) {
//       headers = headers.set('X-Tenant-ID', this.selectedTenant);
//     }

//     const clonedRequest = req.clone({ headers });

//     return next.handle(clonedRequest);
//   }
// }
