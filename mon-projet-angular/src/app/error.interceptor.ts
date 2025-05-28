import {
  HttpEvent,
  HttpHandler,
  HttpInterceptor,
  HttpRequest,
  HttpErrorResponse
} from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { AuthService } from './auth.service';
import { Router } from '@angular/router';

@Injectable()
export class ErrorInterceptor implements HttpInterceptor {
  constructor(private auth: AuthService, private router: Router) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return next.handle(req).pipe(
      catchError((error: HttpErrorResponse) => {
        // Gestion des erreurs 401/403
        if (error.status === 401 || error.status === 403) {
          console.warn('Erreur d\'authentification détectée, déconnexion...');
          this.auth.logout(); // Appel logout pour effacer le token
          this.router.navigate(['/']); // Redirection vers accueil ou login
        }

        return throwError(() => error);
      })
    );
  }
}
