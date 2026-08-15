/**
 * Configuration Service for NetSec Platform
 * 
 * Provides type-safe API client for configuration operations.
 */

import axios from 'axios';
import type {
  ConfigurationSchema,
  ConfigSchemaResponse,
  ConfigStatusResponse,
  ConfigUpdateRequest,
  ConfigValidateRequest,
  ConfigChangeDiff
} from '../types/config';

const API_BASE = '/api/v1/config';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add auth token to requests
api.interceptors.request.use(config => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle errors
api.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 403) {
      throw new Error('Permission denied: Insufficient privileges for configuration access');
    }
    throw error;
  }
);

export const configService = {
  /**
   * Get effective configuration with redacted secrets
   */
  async getConfiguration(): Promise<ConfigurationSchema> {
    const response = await api.get('');
    return response.data;
  },

  /**
   * Get configuration schema with metadata
   */
  async getSchema(): Promise<ConfigSchemaResponse> {
    const response = await api.get('/schema');
    return response.data;
  },

  /**
   * Get configuration health status
   */
  async getStatus(): Promise<ConfigStatusResponse> {
    const response = await api.get('/status');
    return response.data;
  },

  /**
   * Update a single configuration setting
   */
  async updateSetting(path: string, value: any): Promise<{
    status: string;
    path: string;
    value: any;
    restart_required: boolean;
    message: string;
  }> {
    const request: ConfigUpdateRequest = { path, value };
    const response = await api.patch(`/${path}`, request);
    return response.data;
  },

  /**
   * Update entire configuration atomically
   */
  async updateConfiguration(config: Partial<ConfigurationSchema>): Promise<{
    status: string;
    message: string;
    requires_restart: boolean;
  }> {
    const response = await api.put('', { configuration: config });
    return response.data;
  },

  /**
   * Validate configuration without applying
   */
  async validateConfiguration(config: Partial<ConfigurationSchema>): Promise<{
    valid: boolean;
    message: string;
    errors: string[];
  }> {
    const request: ConfigValidateRequest = { configuration: config };
    const response = await api.post('/validate', request);
    return response.data;
  },

  /**
   * Reload configuration from all sources
   */
  async reloadConfiguration(): Promise<{
    status: string;
    message: string;
    version_hash: string;
  }> {
    const response = await api.post('/reload');
    return response.data;
  },

  /**
   * Calculate diff between current and proposed configuration
   */
  calculateDiff(
    current: ConfigurationSchema,
    proposed: Partial<ConfigurationSchema>
  ): ConfigChangeDiff[] {
    const diffs: ConfigChangeDiff[] = [];
    
    for (const [section, values] of Object.entries(proposed)) {
      if (typeof values !== 'object' || values === null) continue;
      
      for (const [key, newValue] of Object.entries(values)) {
        const path = `${section}.${key}`;
        const currentValue = (current as any)[section]?.[key];
        
        if (JSON.stringify(currentValue) !== JSON.stringify(newValue)) {
          diffs.push({
            path,
            before: currentValue,
            after: newValue,
            restartRequired: false, // Would need metadata lookup
            securityCritical: false, // Would need metadata lookup
            description: `Changed ${path}`
          });
        }
      }
    }
    
    return diffs;
  }
};

export default configService;
