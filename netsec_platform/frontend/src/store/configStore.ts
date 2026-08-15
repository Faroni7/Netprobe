/**
 * Configuration Store using Zustand
 * 
 * Manages application configuration state in the frontend.
 */

import { create } from 'zustand';
import type { ConfigurationSchema, ConfigSchemaResponse, ConfigStatusResponse } from '../types/config';
import { configService } from '../services/configService';

interface ConfigState {
  // State
  configuration: ConfigurationSchema | null;
  schema: ConfigSchemaResponse | null;
  status: ConfigStatusResponse | null;
  loading: boolean;
  error: string | null;
  hasUnsavedChanges: boolean;
  pendingChanges: Record<string, any>;
  
  // Actions
  loadConfiguration: () => Promise<void>;
  loadSchema: () => Promise<void>;
  loadStatus: () => Promise<void>;
  updateSetting: (path: string, value: any) => Promise<boolean>;
  validateChanges: () => Promise<{ valid: boolean; message: string }>;
  saveChanges: () => Promise<boolean>;
  discardChanges: () => void;
  resetToDefaults: (section?: string) => Promise<void>;
}

export const useConfigStore = create<ConfigState>((set, get) => ({
  // Initial state
  configuration: null,
  schema: null,
  status: null,
  loading: false,
  error: null,
  hasUnsavedChanges: false,
  pendingChanges: {},
  
  /**
   * Load current configuration from backend
   */
  loadConfiguration: async () => {
    set({ loading: true, error: null });
    try {
      const config = await configService.getConfiguration();
      set({ configuration: config, loading: false });
    } catch (error: any) {
      set({ 
        error: error.message || 'Failed to load configuration',
        loading: false 
      });
    }
  },
  
  /**
   * Load configuration schema
   */
  loadSchema: async () => {
    try {
      const schema = await configService.getSchema();
      set({ schema });
    } catch (error: any) {
      console.error('Failed to load schema:', error);
    }
  },
  
  /**
   * Load configuration status
   */
  loadStatus: async () => {
    try {
      const status = await configService.getStatus();
      set({ status });
    } catch (error: any) {
      console.error('Failed to load status:', error);
    }
  },
  
  /**
   * Update a single setting (adds to pending changes)
   */
  updateSetting: async (path: string, value: any) => {
    const { pendingChanges } = get();
    
    // Add to pending changes
    const [section, key] = path.split('.');
    set({
      pendingChanges: {
        ...pendingChanges,
        [section]: {
          ...(pendingChanges[section] || {}),
          [key]: value
        }
      },
      hasUnsavedChanges: true
    });
    
    return true;
  },
  
  /**
   * Validate pending changes against backend
   */
  validateChanges: async () => {
    const { pendingChanges, configuration } = get();
    
    if (Object.keys(pendingChanges).length === 0) {
      return { valid: true, message: 'No changes to validate' };
    }
    
    try {
      // Merge pending changes with current config for validation
      const proposedConfig = {
        ...configuration,
        ...pendingChanges
      };
      
      const result = await configService.validateConfiguration(proposedConfig);
      return result;
    } catch (error: any) {
      return { valid: false, message: error.message };
    }
  },
  
  /**
   * Save all pending changes to backend
   */
  saveChanges: async () => {
    const { pendingChanges } = get();
    
    if (Object.keys(pendingChanges).length === 0) {
      return true;
    }
    
    try {
      await configService.updateConfiguration(pendingChanges);
      
      // Clear pending changes and reload
      set({
        pendingChanges: {},
        hasUnsavedChanges: false
      });
      
      await get().loadConfiguration();
      return true;
    } catch (error: any) {
      set({ error: error.message });
      return false;
    }
  },
  
  /**
   * Discard all pending changes
   */
  discardChanges: () => {
    set({
      pendingChanges: {},
      hasUnsavedChanges: false
    });
  },
  
  /**
   * Reset a section or entire config to defaults
   */
  resetToDefaults: async (section?: string) => {
    // This would require backend support for default values
    console.log('Reset to defaults not yet implemented', section);
  }
}));
