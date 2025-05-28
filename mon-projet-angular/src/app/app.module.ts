
import { NgModule,importProvidersFrom } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppComponent } from './app.component';
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { AuthInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';
import { OAuthModule } from 'angular-oauth2-oidc';
import { ErrorInterceptor } from './error.interceptor';
@NgModule({
  declarations: [AppComponent],
  imports: [BrowserModule, OAuthModule.forRoot()],
  providers: [
    AuthService,
    provideHttpClient(withInterceptorsFromDi()),
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true },
    { provide: HTTP_INTERCEPTORS, useClass: ErrorInterceptor, multi: true }
  ],
  
  bootstrap: [AppComponent],
})
export class AppModule {}   
