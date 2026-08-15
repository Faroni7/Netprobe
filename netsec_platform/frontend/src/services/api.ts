import axios, { AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import type { AuthToken } from '@/types';

const API_BASE_URL = '/api';

class ApiService {
  private client: AxiosInstance;
  private token: string | null = null;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor to add auth token
    this.client.interceptors.request.use((config: InternalAxiosRequestConfig) => {
      if (this.token) {
        config.headers.Authorization = `Bearer ${this.token}`;
      }
      return config;
    });

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          this.token = null;
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  setToken(token: string) {
    this.token = token;
    localStorage.setItem('access_token', token);
  }

  getToken(): string | null {
    if (this.token) {
      return this.token;
    }
    const stored = localStorage.getItem('access_token');
    this.token = stored;
    return stored;
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('access_token');
  }

  // Capture endpoints
  async getCaptureStatus() {
    const response = await this.client.get('/capture/status');
    return response.data;
  }

  async startCapture(interfaceName: string, profile: string) {
    const response = await this.client.post('/capture/start', {
      interface: interfaceName,
      profile,
    });
    return response.data;
  }

  async stopCapture() {
    const response = await this.client.post('/capture/stop');
    return response.data;
  }

  async getInterfaces() {
    const response = await this.client.get('/capture/interfaces');
    return response.data;
  }

  // ESS endpoints
  async getESSStatus() {
    const response = await this.client.get('/ess/status');
    return response.data;
  }

  async activateESS(reason: string) {
    const response = await this.client.post('/ess/activate', { reason });
    return response.data;
  }

  async recoverESS(authorization: string, reason: string) {
    const response = await this.client.post('/ess/recover', {
      authorization,
      reason,
    });
    return response.data;
  }

  // Dashboard endpoints
  async getDashboardStats() {
    const response = await this.client.get('/dashboard/stats');
    return response.data;
  }

  // Flow endpoints
  async getFlows(filters?: Record<string, any>, limit = 100) {
    const response = await this.client.get('/flows', {
      params: { ...filters, limit },
    });
    return response.data;
  }

  async getFlowById(fid: string) {
    const response = await this.client.get(`/flows/${fid}`);
    return response.data;
  }

  // Finding endpoints
  async getFindings(filters?: Record<string, any>) {
    const response = await this.client.get('/findings', {
      params: filters,
    });
    return response.data;
  }

  async getFindingById(findingId: string) {
    const response = await this.client.get(`/findings/${findingId}`);
    return response.data;
  }

  async updateFindingStatus(findingId: string, status: string) {
    const response = await this.client.patch(`/findings/${findingId}/status`, {
      status,
    });
    return response.data;
  }

  // Evidence endpoints
  async getEvidence(filters?: Record<string, any>) {
    const response = await this.client.get('/evidence', {
      params: filters,
    });
    return response.data;
  }

  async getEvidenceById(eid: string) {
    const response = await this.client.get(`/evidence/${eid}`);
    return response.data;
  }

  async revealSensitiveValue(eid: string, reason: string) {
    const response = await this.client.post(`/evidence/${eid}/reveal`, {
      reason,
    });
    return response.data;
  }

  // Asset endpoints
  async getAssets() {
    const response = await this.client.get('/assets');
    return response.data;
  }

  async getAssetByIp(ip: string) {
    const response = await this.client.get(`/assets/${ip}`);
    return response.data;
  }

  // DNS endpoints
  async getDNSRecords(filters?: Record<string, any>) {
    const response = await this.client.get('/dns', {
      params: filters,
    });
    return response.data;
  }

  // Search endpoint
  async search(query: string, limit = 100) {
    const response = await this.client.get('/search', {
      params: { q: query, limit },
    });
    return response.data;
  }

  // Case endpoints
  async getCases() {
    const response = await this.client.get('/cases');
    return response.data;
  }

  async createCase(caseData: Partial<any>) {
    const response = await this.client.post('/cases', caseData);
    return response.data;
  }

  async getCaseById(caseId: string) {
    const response = await this.client.get(`/cases/${caseId}`);
    return response.data;
  }

  // Report endpoints
  async generateReport(reportType: string, options?: Record<string, any>) {
    const response = await this.client.post('/reports/generate', {
      type: reportType,
      options,
    });
    return response.data;
  }

  // Auth endpoints
  async login(username: string, password: string) {
    const response = await this.client.post('/auth/login', {
      username,
      password,
    });
    const tokenData = response.data as AuthToken;
    this.setToken(tokenData.access_token);
    return tokenData;
  }

  async logout() {
    await this.client.post('/auth/logout');
    this.clearToken();
  }

  async getCurrentUser() {
    const response = await this.client.get('/auth/me');
    return response.data;
  }
}

export const apiService = new ApiService();
export default apiService;
