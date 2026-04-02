import type { ContentTypeDef } from '@vqr/shared';

import { getAllContentTypes } from '@vqr/shared';

import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import ButtonBase from '@mui/material/ButtonBase';
import { alpha, useTheme } from '@mui/material/styles';

// Category icons as emoji fallbacks for content types
const TYPE_EMOJIS: Record<string, string> = {
  url: '🔗',
  vcard: '👤',
  coupon: '🎫',
  event: '📅',
  pdf: '📄',
  business: '🏪',
  social: '🔗',
  feedback: '⭐',
};

type Props = {
  selected: string | null;
  onSelect: (typeId: string) => void;
};

export function ContentTypePicker({ selected, onSelect }: Props) {
  const theme = useTheme();
  const types = getAllContentTypes();

  return (
    <Grid container spacing={2}>
      {types.map((t: ContentTypeDef) => {
        const isSelected = selected === t.id;
        return (
          <Grid key={t.id} size={{ xs: 6, sm: 4, md: 3 }}>
            <ButtonBase
              onClick={() => onSelect(t.id)}
              sx={{
                p: 2.5,
                width: '100%',
                borderRadius: 2,
                flexDirection: 'column',
                border: '2px solid',
                borderColor: isSelected ? 'primary.main' : 'divider',
                bgcolor: isSelected ? alpha(theme.palette.primary.main, 0.08) : 'transparent',
                transition: 'all 0.2s',
                '&:hover': {
                  bgcolor: alpha(theme.palette.primary.main, 0.04),
                  borderColor: isSelected ? 'primary.main' : 'text.disabled',
                },
                ...(!t.freeTierAllowed && { opacity: 0.7 }),
              }}
            >
              <Typography sx={{ fontSize: 32, mb: 1 }}>{TYPE_EMOJIS[t.id] || '📋'}</Typography>
              <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 0.5 }}>
                {t.label}
              </Typography>
              <Typography variant="caption" color="text.secondary" sx={{ lineHeight: 1.3 }}>
                {t.description}
              </Typography>
              {!t.freeTierAllowed && (
                <Typography variant="caption" sx={{ mt: 0.5, color: 'warning.main', fontWeight: 600 }}>
                  Pro
                </Typography>
              )}
            </ButtonBase>
          </Grid>
        );
      })}
    </Grid>
  );
}
