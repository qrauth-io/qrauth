import type { ContentFieldDef } from '@vqr/shared';

import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';

// Simple dynamic form that renders fields from the content type registry
type Props = {
  fields: ContentFieldDef[];
  values: Record<string, any>;
  onChange: (name: string, value: any) => void;
};

export function ContentForm({ fields, values, onChange }: Props) {
  const renderField = (field: ContentFieldDef) => {
    const value = field.name.includes('.')
      ? field.name.split('.').reduce((obj: any, key) => obj?.[key], values)
      : values[field.name];

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

      case 'address':
        return (
          <Stack key={field.name} spacing={1.5}>
            <Typography variant="subtitle2" color="text.secondary">
              {field.label}
            </Typography>
            {['street', 'city', 'state', 'zip', 'country'].map((sub) => (
              <TextField
                key={`${field.name}.${sub}`}
                label={sub.charAt(0).toUpperCase() + sub.slice(1)}
                value={values[field.name]?.[sub] || ''}
                onChange={(e) => {
                  const current = values[field.name] || {};
                  onChange(field.name, { ...current, [sub]: e.target.value });
                }}
                size="small"
                fullWidth
                slotProps={{ inputLabel: { shrink: true } }}
              />
            ))}
          </Stack>
        );

      case 'social-links':
        return (
          <Stack key={field.name} spacing={1}>
            <Typography variant="subtitle2" color="text.secondary">
              {field.label}
            </Typography>
            <Typography variant="caption" color="text.disabled">
              {field.helpText}
            </Typography>
            {(values[field.name] || [{ platform: '', url: '' }]).map(
              (link: { platform: string; url: string }, i: number) => (
                <Stack key={i} direction="row" spacing={1}>
                  <TextField
                    label="Platform"
                    value={link.platform || ''}
                    onChange={(e) => {
                      const links = [...(values[field.name] || [])];
                      links[i] = { ...links[i], platform: e.target.value };
                      onChange(field.name, links);
                    }}
                    size="small"
                    sx={{ width: 140 }}
                    placeholder="LinkedIn"
                    slotProps={{ inputLabel: { shrink: true } }}
                  />
                  <TextField
                    label="URL"
                    value={link.url || ''}
                    onChange={(e) => {
                      const links = [...(values[field.name] || [])];
                      links[i] = { ...links[i], url: e.target.value };
                      onChange(field.name, links);
                    }}
                    size="small"
                    fullWidth
                    placeholder="https://linkedin.com/in/..."
                    slotProps={{ inputLabel: { shrink: true } }}
                  />
                </Stack>
              )
            )}
            <Typography
              variant="caption"
              sx={{ color: 'primary.main', cursor: 'pointer' }}
              onClick={() =>
                onChange(field.name, [
                  ...(values[field.name] || []),
                  { platform: '', url: '' },
                ])
              }
            >
              + Add link
            </Typography>
          </Stack>
        );

      case 'image':
        return (
          <TextField
            key={field.name}
            label={field.label}
            value={value || ''}
            onChange={(e) => onChange(field.name, e.target.value)}
            placeholder="https://example.com/image.jpg"
            fullWidth
            helperText={field.helpText || 'Enter image URL (file upload coming soon)'}
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

  // Group fields by group property
  const groups: Record<string, ContentFieldDef[]> = {};
  const ungrouped: ContentFieldDef[] = [];

  for (const field of fields) {
    if (field.group) {
      if (!groups[field.group]) groups[field.group] = [];
      groups[field.group].push(field);
    } else {
      ungrouped.push(field);
    }
  }

  return (
    <Stack spacing={2.5}>
      {/* Render grouped fields side by side */}
      {Object.entries(groups).map(([groupName, groupFields]) => (
        <Stack key={groupName} spacing={1.5}>
          <Typography variant="subtitle2" color="text.secondary">
            {groupName}
          </Typography>
          <Stack direction="row" spacing={1.5}>
            {groupFields.map(renderField)}
          </Stack>
        </Stack>
      ))}
      {/* Render ungrouped fields */}
      {ungrouped.map(renderField)}
    </Stack>
  );
}
