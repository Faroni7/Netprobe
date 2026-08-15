/**
 * Configuration Diff Component
 * 
 * Shows before/after comparison of configuration changes with warnings.
 */

import React from 'react';
import { Box, Typography, Paper, Alert, Chip } from '@mui/material';
import type { ConfigChangeDiff } from '../../types/config';

interface ConfigDiffProps {
  diffs: ConfigChangeDiff[];
}

export const ConfigDiff: React.FC<ConfigDiffProps> = ({ diffs }) => {
  if (diffs.length === 0) {
    return (
      <Alert severity="info">
        No configuration changes detected
      </Alert>
    );
  }

  const hasSecurityCritical = diffs.some(d => d.securityCritical);
  const hasRestartRequired = diffs.some(d => d.restartRequired);

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Typography variant="h6" gutterBottom>
        Configuration Changes ({diffs.length})
      </Typography>

      {hasSecurityCritical && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          <strong>Security Critical:</strong> Some changes affect security boundaries
        </Alert>
      )}

      {hasRestartRequired && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <strong>Restart Required:</strong> Application restart needed for changes to take effect
        </Alert>
      )}

      <Box sx={{ mt: 2 }}>
        {diffs.map((diff, index) => (
          <Box
            key={index}
            sx={{
              p: 2,
              mb: 2,
              bgcolor: 'background.default',
              borderRadius: 1,
              border: '1px solid',
              borderColor: diff.securityCritical ? 'warning.light' : 'divider'
            }}
          >
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="subtitle2" fontFamily="monospace">
                {diff.path}
              </Typography>
              <Box>
                {diff.securityCritical && (
                  <Chip
                    size="small"
                    label="⚠️ Security"
                    color="warning"
                    sx={{ mr: 1 }}
                  />
                )}
                {diff.restartRequired && (
                  <Chip
                    size="small"
                    label="🔄 Restart"
                    color="info"
                  />
                )}
              </Box>
            </Box>

            <Box sx={{ display: 'flex', gap: 3, mt: 2 }}>
              <Box sx={{ flex: 1 }}>
                <Typography variant="caption" color="text.secondary">
                  Before
                </Typography>
                <Box
                  sx={{
                    p: 1,
                    bgcolor: 'error.light',
                    borderRadius: 1,
                    fontFamily: 'monospace',
                    fontSize: '0.875rem'
                  }}
                >
                  {formatValue(diff.before)}
                </Box>
              </Box>

              <Box sx={{ flex: 1 }}>
                <Typography variant="caption" color="text.secondary">
                  After
                </Typography>
                <Box
                  sx={{
                    p: 1,
                    bgcolor: 'success.light',
                    borderRadius: 1,
                    fontFamily: 'monospace',
                    fontSize: '0.875rem'
                  }}
                >
                  {formatValue(diff.after)}
                </Box>
              </Box>
            </Box>

            {diff.description && (
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                {diff.description}
              </Typography>
            )}
          </Box>
        ))}
      </Box>
    </Paper>
  );
};

function formatValue(value: any): string {
  if (value === null || value === undefined) {
    return '<null>';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (Array.isArray(value)) {
    return `[${value.join(', ')}]`;
  }
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  // Redact secrets
  if (typeof value === 'string' && value.length > 20 && !value.includes(' ')) {
    return value.substring(0, 4) + '••••' + value.substring(value.length - 4);
  }
  return String(value);
}

export default ConfigDiff;
