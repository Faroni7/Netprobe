/**
 * Secret Field Component
 * 
 * Displays redacted values for sensitive configuration.
 */

import React, { useState } from 'react';
import { TextField, InputAdornment, IconButton, Box, Alert } from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';

interface SecretFieldProps {
  label: string;
  value: string | null;
  onChange: (value: string) => void;
  description?: string;
  disabled?: boolean;
}

export const SecretField: React.FC<SecretFieldProps> = ({
  label,
  value,
  onChange,
  description,
  disabled = false
}) => {
  const [showValue, setShowValue] = useState(false);
  const [localValue, setLocalValue] = useState('');

  const isConfigured = value !== null && value !== undefined;

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setLocalValue(e.target.value);
    onChange(e.target.value);
  };

  return (
    <Box sx={{ mb: 3 }}>
      <Alert severity="warning" sx={{ mb: 2 }} icon={false}>
        <strong>Sensitive Setting:</strong> This value is encrypted and access is audited.
      </Alert>

      <TextField
        label={label}
        type={showValue ? 'text' : 'password'}
        value={showValue ? (value || localValue) : '••••••••••••••••'}
        onChange={handleChange}
        disabled={disabled}
        fullWidth
        placeholder={isConfigured ? '<Leave blank to keep current value>' : '<SET_VIA_ENVIRONMENT>'}
        InputProps={{
          endAdornment: (
            <InputAdornment position="end">
              <IconButton
                onClick={() => setShowValue(!showValue)}
                edge="end"
                disabled={!isConfigured && !localValue}
              >
                {showValue ? <VisibilityOff /> : <Visibility />}
              </IconButton>
            </InputAdornment>
          )
        }}
        helperText={description}
        variant="outlined"
      />

      {!isConfigured && (
        <Alert severity="info" sx={{ mt: 2 }}>
          This secret should be set via environment variable (NETSEC_*) in production environments.
        </Alert>
      )}
    </Box>
  );
};

export default SecretField;
