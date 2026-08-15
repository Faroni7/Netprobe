import { Box, Typography, Paper } from '@mui/material';

interface PlaceholderPageProps {
  title: string;
  description?: string;
}

export default function PlaceholderPage({ title, description }: PlaceholderPageProps) {
  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        {title}
      </Typography>
      <Paper sx={{ p: 4, bgcolor: '#1e1e1e', textAlign: 'center' }}>
        <Typography variant="h6" color="text.secondary">
          {description || `${title} page - Coming soon`}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          This module is under development.
        </Typography>
      </Paper>
    </Box>
  );
}
