// src/app/user.service.ts
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class UserService {
  private baseUrl = 'http://localhost:8082/multi-auth/api';

  constructor(private http: HttpClient) {}

  getUser(): Observable<string> {
    return this.http.get(`${this.baseUrl}/user`, { responseType: 'text' });
  }

  getAdmin(): Observable<string> {
    return this.http.get(`${this.baseUrl}/admin`, { responseType: 'text' });
  }
}