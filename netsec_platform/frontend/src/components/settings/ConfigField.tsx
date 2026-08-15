/**
 * Configuration Field Component
 * 
 * Smart field renderer that auto-detects types and renders appropriate input.
 */

import React from 'react';
import { TextField, Switch, Select, MenuItem, FormControl, FormLabel, FormHelperText, Box } from '@mui/material';
import type { ConfigFieldDefinition } from '../../types/config';

interface ConfigFieldProps {
  field: ConfigFieldDefinition;
  value: any;
  onChange: (value: any) => void;
  error?: string;
}

export const ConfigField: React.FC<ConfigFieldProps> = ({ field, value, onChange, error }) => {
  const renderField = () => {
    switch (field.type) {
      case 'boolean':
        return (
          <Switch
            checked={value}
            onChange={(e) => onChange(e.target.checked)}
            disabled={field.locked}
            color="primary"
          />
        );
        
      case 'enum':
        return (
          <Select
            value={value}
            onChange={(e) => onChange(e.target.value)}
            disabled={field.locked}
            fullWidth
            error={!!error}
          >
            {field.allowedValues?.map((val) => (
              <MenuItem key={val} value={val}>
                {val}
              </MenuItem>
            ))}
          </Select>
        );
        
      case 'number':
        return (
          <TextField
            type="number"
            value={value}
            onChange={(e) => onChange(Number(e.target.value))}
            disabled={field.locked}
            fullWidth
            error={!!error}
            InputProps={{
              inputProps: {
                min: field.minimum,
                max: field.maximum
              }
            }}
          />
        );
        
      case 'secret':
        return (
          <TextField
            type="password"
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            disabled={field.locked}
            fullWidth
            error={!!error}
            placeholder="<SET_VIA_ENVIRONMENT>"
          />
        );
        
      case 'array':
        return (
          <TextField
            value={Array.isArray(value) ? value.join(', ') : ''}
            onChange={(e) => onChange(e.target.value.split(',').map(s => s.trim()))}
            disabled={field.locked}
            fullWidth
            error={!!error}
            helperText="Comma-separated values"
          />
        );
        
      default: // string
        return (
          <TextField
            value={value}
            onChange={(e) => onChange(e.target.value)}
            disabled={field.locked}
            fullWidth
            error={!!error}
          />
        );
    }
  };

  return (
    <Box sx={{ mb: 3 }}>
      <FormControl fullWidth error={!!error}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
          <FormLabel sx={{ fontWeight: field.securityCritical ? 'bold' : 'normal' }}>
            {field.name}
            {field.locked && ' 🔒'}
            {field.securityCritical && ' ⚠️'}
          </FormLabel>
          {field.restartRequired && (
            <Box component="span" sx={{ fontSize: '0.75rem', color: 'warning.main' }}>
              Restart Required
            </Box>
          )}
        </Box>
        
        {renderField()}
        
        <FormHelperText>
          {field.description}
          {field.sensitive && ' (Sensitive - stored encrypted)'}
        </FormHelperText>
        
        {error && (
          <FormHelperText error>
            {error}
          </FormHelperText>
        )}
      </FormControl>
    </Box>
  );
};

export default ConfigField;
