/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'crypto';
import { type Request, type Response, type NextFunction } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export function changePassword () {
  return async ({ query, headers, connection }: Request, res: Response, next: NextFunction) => {
    const currentPassword = query.current as string
    const newPassword = query.new as string
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = query.repeat

    if (!newPassword || crypto.timingSafeEqual(Buffer.from(String(newPassword)), Buffer.from(String('undefined')))) {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    } else if (!crypto.timingSafeEqual(Buffer.from(String(newPassword)), Buffer.from(String(repeatPassword)))) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }

    const token = headers.authorization ? headers.authorization.substr('Bearer='.length) : null
    if (crypto.timingSafeEqual(Buffer.from(String(token)), Buffer.from(String(null)))) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    const loggedInUser = security.authenticatedUsers.get(token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    if (currentPassword && !crypto.timingSafeEqual(Buffer.from(String(security.hash(currentPassword))), Buffer.from(String(loggedInUser.data.password)))) {
      res.status(401).send(res.__('Current password is not correct.'))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        res.status(404).send(res.__('User not found.'))
        return
      }

      await user.update({ password: newPasswordInString })
      challengeUtils.solveIf(
        challenges.changePasswordBenderChallenge,
        () => user.id === 3 && !currentPassword && crypto.timingSafeEqual(Buffer.from(String(user.password)), Buffer.from(String(security.hash('slurmCl4ssic'))))
      )
      res.json({ user })
    } catch (error) {
      next(error)
    }
  }
}
