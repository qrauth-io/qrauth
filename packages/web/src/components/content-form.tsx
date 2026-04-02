import type { ContentFieldDef } from '@vqr/shared';

import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import Button from '@mui/material/Button';
import Divider from '@mui/material/Divider';
import TextField from '@mui/material/TextField';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';

import { Iconify } from 'src/components/iconify';

// ----------------------------------------------------------------------

type Props = {
  fields: ContentFieldDef[];
  values: Record<string, any>;
  onChange: (name: string, value: any) => void;
};

const SOCIAL_PLATFORMS = [
  'LinkedIn',
  'Twitter/X',
  'Facebook',
  'Instagram',
  'GitHub',
  'YouTube',
  'TikTok',
  'Website',
];

export function ContentForm({ fields, values, onChange }: Props) {
  // Separate fields into groups and ungrouped
  const groups = new Map<string, ContentFieldDef[]>();
  const ungrouped: ContentFieldDef[] = [];

  for (const field of fields) {
    if (field.group) {
      if (!groups.has(field.group)) groups.set(field.group, []);
      groups.get(field.group)!.push(field);
    } else {
      ungrouped.push(field);
    }
  }

  const renderField = (field: ContentFieldDef, compact = false) => {
    const value = values[field.name];

    switch (field.type) {
      case 'text':
      case 'url':
      case 'email':
      case 'phone':
      case 'number':
        return (
          <TextField
            key={field.name}
            label={field.label}
            value={value || ''}
            onChange={(e) => onChange(field.name, e.target.value)}
            placeholder={field.placeholder}
            required={field.required}
            type={field.type === 'number' ? 'number' : 'text'}
            size={compact ? 'small' : 'medium'}
            fullWidth
            helperText={field.helpText}
            slotProps={{ inputLabel: { shrink: true } }}
          />
        );

      case 'textarea':
        return (
          <TextField
            key={field.name}
            label={field.label}
            value={value || ''}
            onChange={(e) => onChange(field.name, e.target.value)}
            placeholder={field.placeholder}
            required={field.required}
            multiline
            rows={3}
            fullWidth
            helperText={field.helpText}
            slotProps={{ inputLabel: { shrink: true } }}
          />
        );

      case 'date':
      case 'datetime':
        return (
          <TextField
            key={field.name}
            label={field.label}
            value={value || ''}
            onChange={(e) => onChange(field.name, e.target.value)}
            type={field.type === 'datetime' ? 'datetime-local' : 'date'}
            fullWidth
            helperText={field.helpText}
            slotProps={{ inputLabel: { shrink: true } }}
          />
        );

      case 'image':
        return (
          <TextField
            key={field.name}
            label={field.label}
            value={value || ''}
            onChange={(e) => onChange(field.name, e.target.value)}
            placeholder="https://example.com/photo.jpg"
            fullWidth
            helperText={field.helpText || 'Paste an image URL (file upload coming soon)'}
            slotProps={{ inputLabel: { shrink: true } }}
          />
        );

      case 'file':
        return (
          <TextField
            key={field.name}
            label={field.label}
            value={value || ''}
            onChange={(e) => onChange(field.name, e.target.value)}
            placeholder="File URL"
            fullWidth
            helperText={field.helpText || 'File upload coming soon — enter URL for now'}
            slotProps={{ inputLabel: { shrink: true } }}
          />
        );

      case 'address':
        return (
          <Box key={field.name}>
            <Grid container spacing={1.5}>
              <Grid size={12}>
                <TextField
                  label="Street"
                  value={values[field.name]?.street || ''}
                  onChange={(e) =>
                    onChange(field.name, { ...(values[field.name] || {}), street: e.target.value })
                  }
                  size="small"
                  fullWidth
                  slotProps={{ inputLabel: { shrink: true } }}
                />
              </Grid>
              <Grid size={6}>
                <TextField
                  label="City"
                  value={values[field.name]?.city || ''}
                  onChange={(e) =>
                    onChange(field.name, { ...(values[field.name] || {}), city: e.target.value })
                  }
                  size="small"
                  fullWidth
                  slotProps={{ inputLabel: { shrink: true } }}
                />
              </Grid>
              <Grid size={6}>
                <TextField
                  label="State / Region"
                  value={values[field.name]?.state || ''}
                  onChange={(e) =>
                    onChange(field.name, { ...(values[field.name] || {}), state: e.target.value })
                  }
                  size="small"
                  fullWidth
                  slotProps={{ inputLabel: { shrink: true } }}
                />
              </Grid>
              <Grid size={6}>
                <TextField
                  label="ZIP / Postal"
                  value={values[field.name]?.zip || ''}
                  onChange={(e) =>
                    onChange(field.name, { ...(values[field.name] || {}), zip: e.target.value })
                  }
                  size="small"
                  fullWidth
                  slotProps={{ inputLabel: { shrink: true } }}
                />
              </Grid>
              <Grid size={6}>
                <TextField
                  label="Country"
                  value={values[field.name]?.country || ''}
                  onChange={(e) =>
                    onChange(field.name, { ...(values[field.name] || {}), country: e.target.value })
                  }
                  size="small"
                  fullWidth
                  slotProps={{ inputLabel: { shrink: true } }}
                />
              </Grid>
            </Grid>
          </Box>
        );

      case 'social-links': {
        const links = values[field.name] || [{ platform: '', url: '' }];
        return (
          <Box key={field.name}>
            <Stack spacing={1.5}>
              {links.map((link: any, i: number) => (
                <Stack key={i} direction="row" spacing={1} alignItems="center">
                  <TextField
                    select
                    label="Platform"
                    value={link.platform || ''}
                    onChange={(e) => {
                      const updated = [...links];
                      updated[i] = { ...updated[i], platform: e.target.value };
                      onChange(field.name, updated);
                    }}
                    size="small"
                    sx={{ width: 160 }}
                    slotProps={{ inputLabel: { shrink: true }, select: { native: true } }}
                  >
                    <option value="" />
                    {SOCIAL_PLATFORMS.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </TextField>
                  <TextField
                    label="URL"
                    value={link.url || ''}
                    onChange={(e) => {
                      const updated = [...links];
                      updated[i] = { ...updated[i], url: e.target.value };
                      onChange(field.name, updated);
                    }}
                    size="small"
                    fullWidth
                    placeholder="https://..."
                    slotProps={{ inputLabel: { shrink: true } }}
                  />
                  {links.length > 1 && (
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => {
                        const updated = links.filter((_: any, j: number) => j !== i);
                        onChange(field.name, updated);
                      }}
                    >
                      <Iconify icon="mingcute:close-line" width={18} />
                    </IconButton>
                  )}
                </Stack>
              ))}
              <Button
                size="small"
                startIcon={<Iconify icon="mingcute:add-line" width={16} />}
                onClick={() => onChange(field.name, [...links, { platform: '', url: '' }])}
                sx={{ alignSelf: 'flex-start' }}
              >
                Add link
              </Button>
            </Stack>
          </Box>
        );
      }

      default:
        return (
          <TextField
            key={field.name}
            label={field.label}
            value={value || ''}
            onChange={(e) => onChange(field.name, e.target.value)}
            placeholder={field.placeholder}
            fullWidth
            slotProps={{ inputLabel: { shrink: true } }}
          />
        );
    }
  };

  return (
    <Stack spacing={3}>
      {/* Grouped fields */}
      {Array.from(groups.entries()).map(([groupName, groupFields]) => (
        <Box key={groupName}>
          <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1.5 }}>
            {groupName}
          </Typography>
          {groupFields.length === 2 &&
          !['address', 'social-links'].includes(groupFields[0].type) ? (
            <Stack direction="row" spacing={2}>
              {groupFields.map((f) => renderField(f))}
            </Stack>
          ) : (
            <Stack spacing={2}>{groupFields.map((f) => renderField(f))}</Stack>
          )}
        </Box>
      ))}

      {/* Ungrouped fields — render with dividers before address / social sections */}
      {ungrouped.map((field, i) => (
        <Box key={field.name}>
          {i > 0 && field.type === 'address' && <Divider sx={{ mb: 2 }} />}
          {i > 0 && field.type === 'social-links' && <Divider sx={{ mb: 2 }} />}
          {(field.type === 'address' || field.type === 'social-links') && (
            <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1.5 }}>
              {field.label}
            </Typography>
          )}
          {renderField(field)}
        </Box>
      ))}
    </Stack>
  );
}
