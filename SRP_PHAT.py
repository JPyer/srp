import os
import numpy as np
import soundfile as sf

class SRP_PHAT():

    def __init__(self, pos):
        self.algName = "SRP-PHAT"
        self.pos = np.array(pos)
        self.M = np.size(self.pos, 0)

        self.fs = 16000
        self.fMin = 0
        self.fMax = 255
        self.step = 0.5
        self.lamda = 0.9
        self.frmSize  = 1024
        self.c = 340

        fBin = self.fs * (np.arange(self.fMin, self.fMax, 1, dtype = 'float32')) / self.frmSize
        fBin = np.append(fBin, self.fMax)
        self.theta = np.arange(0, 180, self.step, dtype = 'float32') 
        theta = np.append(self.theta, 180)
        tauMat = np.cos(theta * np.pi / 180)[:, None] * self.pos[None, :] / self.c
        
        self.df = np.exp(-2j*np.pi * fBin[:, None, None] * tauMat[None, :, :])
        self.PhiyE = np.zeros([np.size(fBin, 0), self.M, self.M], dtype = 'float32')


    def rtProc(self, yFrm):
        # Step 1: compute covariance matrix and update the estimate
        yf = np.fft.fft(yFrm, self.frmSize, 1).transpose(1, 0)
        yf = yf / np.abs(yf)
        Phiy = yf[..., None] @ yf[:, None, :].conj()
        self.PhiyE = self.lamda * self.PhiyE + (1 - self.lamda) * Phiy[self.fMin:self.fMax+1, :, :]

        # Step 2: compute the spatial spectrum
        self.Px = ((self.df.conj() @ self.PhiyE[:, :, :]) * self.df).sum(axis = (0, 2))

        # Step 3: update the process
        print("%.1f degree" %(self.theta[np.where(self.Px == np.max(self.Px))]))



def enframe(xm, frmLen, frmShift):
    sigLen, M = xm.shape
    overRate = frmLen / frmShift
    nFrm = int(np.floor(sigLen/frmShift) - overRate + 1)
    xnSeg = np.zeros([frmLen, nFrm, M])
    for index in range(nFrm):
        xnSeg[:, index, :] = xm[index*frmShift:index*frmShift+frmLen, :]
    return xnSeg



if __name__ == "__main__":

    # clear the terminal
    os.system('cls')

    # initialize 'alg' using 'geo'
    geo = [-0.125, -0.075, -0.025, 0.025, 0.075, 0.125]
    alg = SRP_PHAT(pos = geo)

    # load audio file
    xm = np.zeros([2401332, alg.M], dtype = 'float32')
    for mIndex in range(alg.M):
        xm[:, mIndex], fs = sf.read('audio/org_Channel_MIC' + str(mIndex+1) + '.wav')

    xnSeg = enframe(xm, alg.frmSize, alg.frmSize)
    frmLen, nFrm, M = xnSeg.shape

    for frmIndex in range(nFrm):
        # for the input date, ySeg.shape = [M, frmSize]
        ySeg = xnSeg[:, frmIndex, :].transpose(1, 0)
        alg.rtProc(ySeg)