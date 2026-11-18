'use client'
import { useEffect, useState } from 'react'
import { supabase } from '@/lib/supabase'

export default function AdminPanel() {
  const [users, setUsers] = useState<any[]>([])
  useEffect(() => {
    supabase.from('profiles').select('*').then(({ data }) => setUsers(data ?? []))
  }, [])
  return <ul>{users.map((u) => <li key={u.id}>{u.email}</li>)}</ul>
}
