// src/app/app.component.ts
import { Component } from '@angular/core';
import { AuthService } from './auth.service';
import { UserService } from './user.service';

@Component({
  selector: 'app-root',
  standalone:false,
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'] 
    
})
export class AppComponent {
  userResponse:string='';
  adminResponse:string='';
  

  constructor(public auth: AuthService,private userService:UserService) {
    
  }

  loginWithKeycloak() {
    this.auth.loginWithKeycloak();
    setTimeout(() => this.auth.loadUserProfile(), 1000); 
  }

  loginWithOkta() {
    this.auth.loginWithOkta();
    setTimeout(() => this.auth.loadUserProfile(), 1000); 
  }

  logout() {
    this.auth.logout();
  }


  getUser() {
    this.userService.getUser().subscribe({
      next: (res) => (this.userResponse = res),
      error: (err) => (this.userResponse = 'Error: ' + err.message),
    });
  }

  getAdmin() {
    this.userService.getAdmin().subscribe({
      next: (res) => (this.adminResponse = res),
      error: (err) => (this.adminResponse = 'Error: ' + err.message),
    });
  }
}











// // src/app/app.component.ts
// import { Component } from '@angular/core';
// import { AuthService } from './auth.service';
// import { UserService } from './user.service';

// @Component({
//   selector: 'app-root',
//   standalone:false,
//   template: `
//     <div class="container">
//       <h2>Multi-Tenant Login (Keycloak & Okta)</h2>
//       <button (click)="loginWithKeycloak()">Login with Keycloak</button>
//       <button (click)="loginWithOkta()">Login with Okta</button>

//       <div *ngIf="auth.isLoggedIn">
//         <p>Welcome!</p>
//         <pre>{{ auth.identityClaims | json }}</pre>
//         <button (click)="logout()">Logout</button>

//         <hr />
//         <button (click)="getUser()">GET /user</button>
//         <button (click)="getAdmin()">GET /admin</button>

//         <p *ngIf="userResponse"><strong>User:</strong> {{ userResponse }}</p>
//         <p *ngIf="adminResponse"><strong>Admin:</strong> {{ adminResponse }}</p>
//       </div>
//     </div>
//   `,
// })
// export class AppComponent {
//   userResponse:string='';
//   adminResponse:string='';
  

//   constructor(public auth: AuthService,private userService:UserService) {
    
//   }

//   loginWithKeycloak() {
//     this.auth.loginWithKeycloak();
//   }

//   loginWithOkta() {
//     this.auth.loginWithOkta();
//   }

//   logout() {
//     this.auth.logout();
//   }


//   getUser() {
//     this.userService.getUser().subscribe({
//       next: (res) => (this.userResponse = res),
//       error: (err) => (this.userResponse = 'Error: ' + err.message),
//     });
//   }

//   getAdmin() {
//     this.userService.getAdmin().subscribe({
//       next: (res) => (this.adminResponse = res),
//       error: (err) => (this.adminResponse = 'Error: ' + err.message),
//     });
//   }
// }