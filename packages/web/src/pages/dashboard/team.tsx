import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import Select from '@mui/material/Select';
import Avatar from '@mui/material/Avatar';
import MenuItem from '@mui/material/MenuItem';
import TableRow from '@mui/material/TableRow';
import TextField from '@mui/material/TextField';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import Typography from '@mui/material/Typography';
import InputLabel from '@mui/material/InputLabel';
import IconButton from '@mui/material/IconButton';
import CardContent from '@mui/material/CardContent';
import FormControl from '@mui/material/FormControl';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import TableContainer from '@mui/material/TableContainer';
import CircularProgress from '@mui/material/CircularProgress';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';

import { useAuthContext } from 'src/auth/hooks';

// ----------------------------------------------------------------------

type Member = {
  id: string;
  userId: string;
  role: string;
  joinedAt: string;
  user: { id: string; name: string; email: string };
};

const ROLE_COLORS: Record<string, 'primary' | 'info' | 'warning' | 'default' | 'success'> = {
  OWNER: 'primary',
  ADMIN: 'info',
  MANAGER: 'warning',
  MEMBER: 'default',
  VIEWER: 'default',
};

const INVITABLE_ROLES = ['ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'];

export default function TeamPage() {
  const { showSuccess, showError } = useSnackbar();
  const { user } = useAuthContext();
  const orgId = (user as Record<string, unknown> & { organization?: { id: string } })?.organization
    ?.id;

  const [members, setMembers] = useState<Member[]>([]);
  const [loading, setLoading] = useState(true);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('MEMBER');
  const [inviting, setInviting] = useState(false);

  const fetchMembers = useCallback(async () => {
    if (!orgId) return;
    try {
      const res = await axios.get(endpoints.organizations.members(orgId));
      setMembers(res.data.data ?? res.data ?? []);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load team';
      showError(message);
    } finally {
      setLoading(false);
    }
  }, [orgId, showError]);

  useEffect(() => {
    fetchMembers();
  }, [fetchMembers]);

  const handleInvite = async () => {
    if (!orgId) return;
    setInviting(true);
    try {
      await axios.post(endpoints.organizations.invitations(orgId), {
        email: inviteEmail,
        role: inviteRole,
      });
      showSuccess(`Invitation sent to ${inviteEmail}`);
      setInviteOpen(false);
      setInviteEmail('');
      setInviteRole('MEMBER');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to send invitation';
      showError(message);
    } finally {
      setInviting(false);
    }
  };

  const handleRoleChange = async (userId: string, newRole: string) => {
    if (!orgId) return;
    try {
      await axios.patch(`${endpoints.organizations.members(orgId)}/${userId}`, { role: newRole });
      showSuccess('Role updated');
      fetchMembers();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to update role';
      showError(message);
    }
  };

  const handleRemove = async (userId: string, memberName: string) => {
    if (!orgId) return;
    if (!window.confirm(`Remove ${memberName} from the organization?`)) return;
    try {
      await axios.delete(`${endpoints.organizations.members(orgId)}/${userId}`);
      showSuccess('Member removed');
      fetchMembers();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to remove member';
      showError(message);
    }
  };

  const currentUserRole = (user as Record<string, unknown>)?.role as string | undefined;
  const canManage = ['OWNER', 'ADMIN'].includes(currentUserRole ?? '');

  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h4">Team Members</Typography>
        {canManage && (
          <Button
            variant="contained"
            startIcon={<Iconify icon="mingcute:add-line" />}
            onClick={() => setInviteOpen(true)}
          >
            Invite Member
          </Button>
        )}
      </Box>

      <Card>
        {loading ? (
          <CardContent sx={{ textAlign: 'center', py: 5 }}>
            <CircularProgress />
          </CardContent>
        ) : (
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Member</TableCell>
                  <TableCell>Role</TableCell>
                  <TableCell>Joined</TableCell>
                  {canManage && <TableCell align="right">Actions</TableCell>}
                </TableRow>
              </TableHead>
              <TableBody>
                {members.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={canManage ? 4 : 3} sx={{ textAlign: 'center', py: 4 }}>
                      <Typography color="text.secondary">No team members yet.</Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  members.map((member) => (
                    <TableRow key={member.id} hover>
                      <TableCell>
                        <Stack direction="row" alignItems="center" spacing={2}>
                          <Avatar sx={{ width: 36, height: 36, fontSize: 14 }}>
                            {member.user.name.charAt(0).toUpperCase()}
                          </Avatar>
                          <Box>
                            <Typography variant="body2" fontWeight={600}>
                              {member.user.name}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {member.user.email}
                            </Typography>
                          </Box>
                        </Stack>
                      </TableCell>
                      <TableCell>
                        {canManage && member.role !== 'OWNER' ? (
                          <FormControl size="small" sx={{ minWidth: 120 }}>
                            <Select
                              value={member.role}
                              onChange={(e) => handleRoleChange(member.userId, e.target.value)}
                            >
                              {INVITABLE_ROLES.map((r) => (
                                <MenuItem key={r} value={r}>
                                  {r}
                                </MenuItem>
                              ))}
                            </Select>
                          </FormControl>
                        ) : (
                          <Chip
                            label={member.role}
                            color={ROLE_COLORS[member.role] || 'default'}
                            size="small"
                          />
                        )}
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption">
                          {new Date(member.joinedAt).toLocaleDateString()}
                        </Typography>
                      </TableCell>
                      {canManage && (
                        <TableCell align="right">
                          {member.role !== 'OWNER' && (
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => handleRemove(member.userId, member.user.name)}
                            >
                              <Iconify icon="solar:trash-bin-trash-bold" />
                            </IconButton>
                          )}
                        </TableCell>
                      )}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Card>

      {/* Invite Dialog */}
      <Dialog open={inviteOpen} onClose={() => setInviteOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Invite Team Member</DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 1 }}>
            <TextField
              label="Email Address"
              type="email"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              fullWidth
              autoFocus
              slotProps={{ inputLabel: { shrink: true } }}
            />
            <FormControl fullWidth>
              <InputLabel>Role</InputLabel>
              <Select
                value={inviteRole}
                label="Role"
                onChange={(e) => setInviteRole(e.target.value)}
              >
                {INVITABLE_ROLES.map((r) => (
                  <MenuItem key={r} value={r}>
                    {r}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setInviteOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleInvite}
            disabled={!inviteEmail || inviting}
          >
            {inviting ? 'Sending...' : 'Send Invitation'}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
